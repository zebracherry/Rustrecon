
use crate::engine::{Config, Finding, FindingSeverity};
use crate::engine::executor::{sh, avail};
use anyhow::Result;
use colored::*;
use std::path::Path;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Instant;
use tokio::time::{sleep, Duration};

struct Ticker { done: Arc<AtomicBool>, handle: tokio::task::JoinHandle<()> }
impl Ticker {
    fn start(tool: &str, target: &str) -> Self {
        let done  = Arc::new(AtomicBool::new(false));
        let done2 = Arc::clone(&done);
        let label = format!("{} on {}", tool.cyan().bold(), target.yellow());
        let handle = tokio::spawn(async move {
            let start  = Instant::now();
            let frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"];
            let mut i  = 0usize;
            loop {
                if done2.load(Ordering::Relaxed) { break; }
                eprint!("
    {} {} — {}s elapsed   ",
                    frames[i % frames.len()].cyan(), label, start.elapsed().as_secs());
                i += 1;
                sleep(Duration::from_millis(500)).await;
            }
            eprintln!("
    {} {} — done in {}s{}",
                "✓".green().bold(), label, Instant::now().elapsed().as_secs(), " ".repeat(10));
        });
        Self { done, handle }
    }
    async fn finish(self) {
        self.done.store(true, Ordering::Relaxed);
        let _ = self.handle.await;
    }
}

pub async fn run(target: &str, cfg: &Config, base: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let scans = base.join("scans");

    // enum4linux-ng — full null session enum
    if avail("enum4linux-ng") {
        println!("    {} running enum4linux-ng (full null session enum)...", "→".yellow());
        let tick = Ticker::start("enum4linux-ng", target);
        let out = sh(
            &format!("enum4linux-ng -A {} 2>/dev/null", target),
            &scans.join("enum4linux.txt"), 180
        ).await.unwrap_or_default();
        tick.finish().await;
        parse_enum4linux(&out, &mut findings);
    } else if avail("enum4linux") {
        println!("    {} running enum4linux (full null session enum)...", "→".yellow());
        let tick2 = Ticker::start("enum4linux", target);
        let out = sh(
            &format!("enum4linux -a {} 2>/dev/null", target),
            &scans.join("enum4linux.txt"), 180
        ).await.unwrap_or_default();
        parse_enum4linux(&out, &mut findings);
    }

    // smbclient — share listing (null session)
    if avail("smbclient") {
        let out = sh(
            &format!("smbclient -L //{target} -N --no-pass 2>/dev/null"),
            &scans.join("smbclient_shares.txt"), 30
        ).await.unwrap_or_default();
        for line in out.lines() {
            if line.trim_start().starts_with("Disk") || line.contains("IPC$") {
                findings.push(Finding {
                    severity: FindingSeverity::Medium,
                    category: "smb-share".into(),
                    title: format!("SMB share found: {}", line.trim().split_whitespace().next().unwrap_or("")),
                    detail: line.trim().to_string(),
                    tool: "smbclient".into(),
                });
            }
        }
    }

    // smbmap
    if avail("smbmap") {
        let cmd_anon = format!("smbmap -H {} -u '' -p '' 2>/dev/null", target);
        let out = sh(&cmd_anon, &scans.join("smbmap_anon.txt"), 30).await.unwrap_or_default();
        for line in out.lines() {
            if line.contains("READ") || line.contains("WRITE") {
                findings.push(Finding {
                    severity: if line.contains("WRITE") { FindingSeverity::High } else { FindingSeverity::Medium },
                    category: "smb-share".into(),
                    title: format!("SMB access: {}", line.trim().split_whitespace().next().unwrap_or("")),
                    detail: line.trim().to_string(),
                    tool: "smbmap".into(),
                });
            }
        }
        if cfg.creds.has_auth() {
            let cmd_auth = format!("smbmap -H {} -u {} -p {} 2>/dev/null",
                target, cfg.creds.user(), cfg.creds.pass());
            sh(&cmd_auth, &scans.join("smbmap_auth.txt"), 30).await.ok();
        }
    }

    // nmap SMB scripts — vuln checks
    if avail("nmap") {
        println!("    {} nmap SMB vuln scripts (MS17-010, signing check)...", "→".yellow());
        let tick_nmap = Ticker::start("nmap-smb", target);
        let scripts = "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-security-mode,smb2-security-mode,smb-enum-shares,smb-enum-users";
        let cmd = format!("nmap -p 445,139 --script={scripts} -Pn -T4 {target} 2>/dev/null");
        let out = sh(&cmd, &scans.join("nmap_smb_scripts.txt"), 60).await.unwrap_or_default();
        tick_nmap.finish().await;
        for line in out.lines() {
            if line.contains("VULNERABLE") || line.contains("ms17-010") || line.contains("ms08-067") {
                findings.push(Finding {
                    severity: FindingSeverity::Critical,
                    category: "smb-vuln".into(),
                    title: format!("SMB VULNERABILITY: {}", line.trim()),
                    detail: line.trim().to_string(),
                    tool: "nmap-smb-scripts".into(),
                });
            }
            if line.contains("Message signing enabled but not required") {
                findings.push(Finding {
                    severity: FindingSeverity::Medium,
                    category: "smb-config".into(),
                    title: "SMB signing not required (relay attacks possible)".into(),
                    detail: line.trim().to_string(),
                    tool: "nmap-smb-scripts".into(),
                });
            }
        }
    }

    // crackmapexec — if we have creds
    if cfg.creds.has_auth() && avail("crackmapexec") {
        let cmd = format!("crackmapexec smb {} -u {} -p '{}' --shares 2>/dev/null",
            target, cfg.creds.user(), cfg.creds.pass());
        let out = sh(&cmd, &scans.join("cme_smb.txt"), 60).await.unwrap_or_default();
        if out.contains("[+]") && out.contains("Pwn3d!") {
            findings.push(Finding {
                severity: FindingSeverity::Critical,
                category: "smb-auth".into(),
                title: "SMB admin access confirmed (Pwn3d!)".into(),
                detail: out.lines().find(|l| l.contains("Pwn3d!")).unwrap_or("").trim().to_string(),
                tool: "crackmapexec".into(),
            });
        }
    }

    Ok(findings)
}

fn parse_enum4linux(out: &str, findings: &mut Vec<Finding>) {
    for line in out.lines() {
        let low = line.to_lowercase();
        if low.contains("username:") || (low.contains("user") && low.contains("rid")) {
            findings.push(Finding {
                severity: FindingSeverity::Medium,
                category: "smb-user".into(),
                title: format!("SMB user found: {}", line.trim()),
                detail: line.trim().to_string(),
                tool: "enum4linux".into(),
            });
        }
        if low.contains("password policy") && low.contains("minimum") {
            findings.push(Finding {
                severity: FindingSeverity::Info,
                category: "smb-policy".into(),
                title: "Password policy enumerated via SMB".into(),
                detail: line.trim().to_string(),
                tool: "enum4linux".into(),
            });
        }
    }
}
