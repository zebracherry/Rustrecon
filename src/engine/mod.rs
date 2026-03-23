
pub mod classifier;
pub mod executor;
pub mod types;
pub use types::*;

use crate::Cli;
use anyhow::Result;
use colored::*;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Debug,Clone)]
pub struct Creds {
    pub username: Option<String>,
    pub password: Option<String>,
    pub hash:     Option<String>,
    pub domain:   Option<String>,
}
impl Creds {
    pub fn has_auth(&self) -> bool {
        self.username.is_some() && (self.password.is_some() || self.hash.is_some())
    }
    pub fn user(&self)   -> &str { self.username.as_deref().unwrap_or("USERNAME") }
    pub fn pass(&self)   -> &str { self.password.as_deref().unwrap_or("PASSWORD") }
    pub fn domain(&self) -> &str { self.domain.as_deref().unwrap_or("DOMAIN") }
}

#[derive(Debug,Clone,PartialEq)]
pub enum TypeHint { Auto, Linux, Windows, AD }

#[derive(Debug,Clone)]
pub struct Config {
    pub output:       String,
    pub max_scans:    usize,
    pub verbose:      u8,
    pub creds:        Creds,
    pub hint:         TypeHint,
    pub force_ports:  Option<Vec<u16>>,
    pub only:         Option<Vec<String>>,
    pub userlist:     String,
    pub passlist:     String,
}
impl Config {
    pub fn from_cli(cli: &Cli) -> Self {
        let force_ports = cli.ports.as_ref().map(|p| {
            p.split(',').filter_map(|s| s.trim().parse().ok()).collect()
        });
        let only = cli.only.as_ref().map(|s| {
            s.split(',').map(|x| x.trim().to_lowercase()).collect()
        });
        let hint = match cli.target_type.to_lowercase().as_str() {
            "linux"   => TypeHint::Linux,
            "windows" => TypeHint::Windows,
            "ad"      => TypeHint::AD,
            _         => TypeHint::Auto,
        };
        Self {
            output: cli.output.clone(), max_scans: cli.max_scans,
            verbose: cli.verbose, hint, force_ports, only,
            userlist: cli.userlist.clone(), passlist: cli.passlist.clone(),
            creds: Creds {
                username: cli.username.clone(), password: cli.password.clone(),
                hash: cli.hash.clone(), domain: cli.domain.clone(),
            },
        }
    }
    pub fn phase_on(&self, name: &str) -> bool {
        self.only.as_ref().map_or(true, |v| v.iter().any(|p| p == name))
    }
}

pub struct Runner { cfg: Arc<Config> }
impl Runner {
    pub fn new(cfg: Config) -> Self { Self { cfg: Arc::new(cfg) } }
    pub async fn run(self, targets: Vec<String>) -> Result<()> {
        println!("{} {} target(s) queued\n", "[*]".cyan().bold(), targets.len());
        let sem = Arc::new(Semaphore::new(self.cfg.max_scans));
        let mut handles = Vec::new();
        for target in targets {
            let cfg  = Arc::clone(&self.cfg);
            let perm = Arc::clone(&sem).acquire_owned().await?;
            handles.push(tokio::spawn(async move {
                let r = scan_target(&target, &cfg).await;
                drop(perm); r
            }));
        }
        for h in handles {
            match h.await? {
                Ok(res) => print_summary(&res),
                Err(e)  => eprintln!("{} {}", "[!]".red().bold(), e),
            }
        }
        println!("\n{} All scans complete.", "[*]".cyan().bold());
        Ok(())
    }
}

async fn scan_target(target: &str, cfg: &Config) -> Result<ScanResult> {
    let mut res = ScanResult::new(target);
    let base = PathBuf::from(&cfg.output).join(target);
    for d in &["scans","loot","report","exploit"] {
        tokio::fs::create_dir_all(base.join(d)).await?;
    }
    println!("{} [{}] scan started", "[*]".cyan(), target);

    // Phase 1 — port scan
    if cfg.phase_on("portscan") || cfg.only.is_none() {
        step(target, "1/6", "port scanning (rustscan → nmap)");
        res.ports = crate::modules::portscan::run(target, cfg, &base).await.unwrap_or_default();
        res.cmd_log.push(format!("portscan: {} open ports found", res.ports.len()));
    }
    if let Some(forced) = &cfg.force_ports {
        for p in forced {
            res.ports.push(Port { number:*p, proto:"tcp".into(), service:"unknown".into(), version:None });
        }
    }

    // Classify
    let nmap_raw = tokio::fs::read_to_string(base.join("scans/nmap_full.txt")).await.unwrap_or_default();
    res.target_type = classifier::classify(&res.ports, &nmap_raw, cfg);
    println!("  {} [{}] classified: {}", "→".yellow(), target, res.target_type.label().bold().cyan());

    let open: Vec<u16> = res.ports.iter().map(|p| p.number).collect();

    // Phase 2 — web
    let web_ports: Vec<u16> = res.ports.iter().filter(|p| is_web(p.number,&p.service)).map(|p|p.number).collect();
    if !web_ports.is_empty() && (cfg.phase_on("web") || cfg.only.is_none()) {
        step(target, "2/6", &format!("web enum {:?}", web_ports));
        res.findings.extend(crate::modules::web::run(target, cfg, &base, &web_ports).await.unwrap_or_default());
    }

    // Phase 3 — network
    if cfg.phase_on("network") || cfg.only.is_none() {
        step(target, "3/6", "network services (DNS,SMTP,FTP,SNMP,SSH,DB)");
        res.findings.extend(crate::modules::network::run(target, cfg, &base, &open).await.unwrap_or_default());
    }

    // Phase 4 — SMB
    if (open.contains(&445) || open.contains(&139)) && (cfg.phase_on("smb") || cfg.only.is_none()) {
        step(target, "4/6", "SMB enumeration");
        res.findings.extend(crate::modules::smb::run(target, cfg, &base).await.unwrap_or_default());
    }

    // Phase 5 — OS specific
    match res.target_type {
        TargetType::Linux => {
            if cfg.phase_on("linux") || cfg.only.is_none() {
                step(target, "5/6", "Linux enumeration");
                res.findings.extend(crate::modules::linux::run(target, cfg, &base, &open).await.unwrap_or_default());
            }
        }
        TargetType::Windows | TargetType::AD => {
            if cfg.phase_on("windows") || cfg.only.is_none() {
                step(target, "5/6", "Windows enumeration");
                res.findings.extend(crate::modules::windows::run(target, cfg, &base, &open).await.unwrap_or_default());
            }
            if res.target_type == TargetType::AD && (cfg.phase_on("ad") || cfg.only.is_none()) {
                step(target, "5b/6", "Active Directory enumeration");
                res.findings.extend(crate::modules::ad::run(target, cfg, &base).await.unwrap_or_default());
            }
        }
        _ => {}
    }

    // Phase 5c — searchsploit + pattern extraction
    if cfg.phase_on("exploit") || cfg.only.is_none() {
        step(target, "5c/6", "searchsploit version matching + pattern extraction");
        crate::modules::exploit_suggest::run_searchsploit(&mut res, &base).await.ok();
        crate::modules::exploit_suggest::extract_patterns(&mut res, &base).await.ok();
    }

    // Phase 6 — report
    step(target, "6/6", "generating reports");
    build_manual_cmds(&mut res, cfg);
    res.finalize();
    crate::report::write_html(&res, &base).await.ok();
    crate::report::write_findings_md(&res, &base).await.ok();
    crate::report::write_manual_cmds(&res, &base).await.ok();
    crate::report::write_cmd_log(&res, &base).await.ok();
    println!("  {} [{}] output: {}/", "→".yellow(), target, base.display());
    Ok(res)
}

fn build_manual_cmds(res: &mut ScanResult, cfg: &Config) {
    let t  = res.target.clone();
    let u  = cfg.creds.user().to_string();
    let p  = cfg.creds.pass().to_string();
    let d  = cfg.creds.domain().to_string();
    let ul = cfg.userlist.clone();
    let pl = cfg.passlist.clone();

    res.manual_cmds.push(format!("# SSH brute force\nhydra -L {ul} -P {pl} ssh://{t}"));
    res.manual_cmds.push(format!("# FTP brute force\nhydra -L {ul} -P {pl} ftp://{t}"));

    for wp in res.ports.iter().filter(|p| is_web(p.number, &p.service)) {
        let s = if wp.number==443||wp.service.contains("ssl"){"https"}else{"http"};
        let port = wp.number;
        res.manual_cmds.push(format!("# Dir brute (big wordlist)\nferoxbuster -u {s}://{t}:{port} -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php,asp,aspx,jsp,txt,html -t 50"));
        res.manual_cmds.push(format!("# Nikto\nnikto -h {s}://{t}:{port}"));
        res.manual_cmds.push(format!("# Nuclei\nnuclei -u {s}://{t}:{port} -severity medium,high,critical"));
        res.manual_cmds.push(format!("# WPScan\nwpscan --url {s}://{t}:{port} --enumerate p,t,u"));
    }
    if res.ports.iter().any(|p| p.number==445) {
        res.manual_cmds.push(format!("# CrackMapExec SMB\ncrackmapexec smb {t} -u {u} -p {p} --shares"));
        res.manual_cmds.push(format!("# SMB null session\nsmbclient -L //{t} -N"));
        res.manual_cmds.push(format!("# Impacket smbexec\nimpacket-smbexec {d}/{u}:{p}@{t}"));
        res.manual_cmds.push(format!("# smbmap\nsmbmap -H {t} -u {u} -p {p}"));
    }
    if res.ports.iter().any(|p| p.number==5985||p.number==5986) {
        res.manual_cmds.push(format!("# Evil-WinRM\nevil-winrm -i {t} -u {u} -p {p}"));
    }
    if res.ports.iter().any(|p| p.number==3389) {
        res.manual_cmds.push(format!("# xfreerdp\nxfreerdp /v:{t} /u:{u} /p:{p} +clipboard /dynamic-resolution"));
    }
    if res.ports.iter().any(|p| p.number==3306) {
        res.manual_cmds.push(format!("# MySQL\nhydra -L {ul} -P {pl} mysql://{t}"));
    }
    if res.ports.iter().any(|p| p.number==1433) {
        res.manual_cmds.push(format!("# MSSQL\nimpacket-mssqlclient {d}/{u}:{p}@{t} -windows-auth"));
    }
    if res.target_type == TargetType::AD {
        res.manual_cmds.push(format!("# BloodHound\nbloodhound-python -c All -u {u} -p {p} -d {d} -ns {t}"));
        res.manual_cmds.push(format!("# AS-REP Roast\nimpacket-GetNPUsers {d}/ -dc-ip {t} -usersfile /tmp/users.txt -no-pass -outputfile asrep.txt"));
        res.manual_cmds.push(format!("# Kerberoast\nimpacket-GetUserSPNs {d}/{u}:{p} -dc-ip {t} -outputfile kerberoast.txt"));
        res.manual_cmds.push(format!("# secretsdump\nimpacket-secretsdump {d}/{u}:'{p}'@{t}"));
        res.manual_cmds.push("# Responder\nsudo responder -I eth0 -rdwv".to_string());
        res.manual_cmds.push(format!("# Kerbrute\nkerbrute userenum -d {d} --dc {t} /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"));
    }
}

fn step(target: &str, phase: &str, msg: &str) {
    // Parse "2/6" style phase strings to draw overall progress bar
    let bar = if let Some((num, den)) = parse_phase(phase) {
        let filled = (num * 16) / den;
        let empty  = 16 - filled;
        format!("[{}{}] {}/{}",
            "█".repeat(filled),
            "░".repeat(empty),
            num, den)
    } else {
        format!("[{:16}] {}", "?", phase)
    };
    println!("  {} {} [{}] {} — {}",
        "→".yellow(), bar.cyan(), target, phase.cyan(), msg);
}

fn parse_phase(phase: &str) -> Option<(usize, usize)> {
    let parts: Vec<&str> = phase.split('/').collect();
    if parts.len() != 2 { return None; }
    // Handle "5b" etc
    let num_str = parts[0].trim_end_matches(|c: char| c.is_alphabetic());
    let num: usize = num_str.parse().ok()?;
    let den: usize = parts[1].parse().ok()?;
    Some((num, den))
}
fn is_web(port: u16, svc: &str) -> bool {
    svc.to_lowercase().contains("http") || matches!(port,80|443|8080|8443|8000|8888|3000|5000|9090|4443)
}
fn print_summary(res: &ScanResult) {
    println!("\n{} [{}] done — {} ports, {} findings",
        "[+]".green().bold(), res.target, res.ports.len(), res.findings.len());
    for f in res.findings.iter().filter(|f| matches!(f.severity, FindingSeverity::Critical|FindingSeverity::High)) {
        println!("  [{}] {} — {}", f.severity.label(), f.title.bold(), f.detail);
    }
}
