
use crate::engine::{Config, Port};
use crate::engine::executor::{sh, avail};
use anyhow::Result;
use regex::Regex;
use std::path::Path;

pub async fn run(target: &str, cfg: &Config, base: &Path) -> Result<Vec<Port>> {
    let scans = base.join("scans");
    tokio::fs::create_dir_all(&scans).await?;
    let tout = 7200u64;

    // Step 1: fast sweep
    let port_list = if avail("rustscan") {
        let cmd = format!("rustscan -a {} --ulimit 5000 -b 1500 --range 1-65535 -- -Pn 2>/dev/null \
            | grep -oP '^[0-9]+(?=/tcp)' | sort -un | paste -sd,", target);
        sh(&cmd, &scans.join("rustscan.txt"), 120).await.unwrap_or_default().trim().to_string()
    } else {
        let cmd = format!("nmap -p- --min-rate 5000 -T4 -Pn --open {} 2>/dev/null \
            | grep '/tcp' | cut -d'/' -f1 | paste -sd,", target);
        sh(&cmd, &scans.join("nmap_sweep.txt"), 300).await.unwrap_or_default().trim().to_string()
    };

    let ports_arg = if port_list.is_empty() { "1-65535".to_string() } else { port_list };

    // Step 2: nmap deep scan
    let nmap_txt = scans.join("nmap_full.txt");
    let nmap_xml = scans.join("nmap_full.xml");
    let cmd = format!(
        "nmap -sV -sC -A -O --version-intensity 5 -p {} -oN {} -oX {} --reason -Pn -T4 {} 2>&1",
        ports_arg, nmap_txt.display(), nmap_xml.display(), target
    );
    sh(&cmd, &scans.join("nmap_full_run.log"), tout).await.ok();

    // Step 3: UDP top 200
    let cmd_udp = format!("nmap -sU --top-ports 200 -oN {} --reason -Pn -T4 {} 2>&1",
        scans.join("nmap_udp.txt").display(), target);
    sh(&cmd_udp, &scans.join("nmap_udp_run.log"), tout/2).await.ok();

    let raw = tokio::fs::read_to_string(&nmap_txt).await.unwrap_or_default();
    Ok(parse_nmap(&raw))
}

pub fn parse_nmap(raw: &str) -> Vec<Port> {
    let re = Regex::new(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)").unwrap();
    let mut out = Vec::new();
    for line in raw.lines() {
        if let Some(c) = re.captures(line.trim()) {
            let port: u16 = c[1].parse().unwrap_or(0);
            if port == 0 { continue; }
            let ver = c[4].trim().to_string();
            out.push(Port {
                number:  port,
                proto:   c[2].to_string(),
                service: c[3].to_string(),
                version: if ver.is_empty() { None } else { Some(ver) },
            });
        }
    }
    out
}
