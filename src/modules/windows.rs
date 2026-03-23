
use crate::engine::{Config, Finding, FindingSeverity};
use crate::engine::executor::{sh, avail};
use anyhow::Result;
use std::path::Path;

pub async fn run(target: &str, cfg: &Config, base: &Path, ports: &[u16]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let scans = base.join("scans");

    // RPC / DCOM
    if ports.contains(&135) {
        if avail("nmap") {
            sh(&format!("nmap -p 135 --script=msrpc-enum -Pn {} 2>/dev/null", target),
                &scans.join("rpc_enum.txt"), 30).await.ok();
        }
    }

    // WinRM
    if ports.contains(&5985) || ports.contains(&5986) {
        if avail("nmap") {
            sh(&format!("nmap -p 5985,5986 --script=http-auth-finder -Pn {} 2>/dev/null", target),
                &scans.join("winrm_check.txt"), 30).await.ok();
        }
        findings.push(Finding {
            severity: FindingSeverity::Medium,
            category: "winrm".into(),
            title: "WinRM open — remote management possible".into(),
            detail: format!("WinRM on {}:{}", target,
                if ports.contains(&5985) {5985} else {5986}),
            tool: "portscan".into(),
        });
    }

    // RDP check
    if ports.contains(&3389) {
        if avail("nmap") {
            let out = sh(
                &format!("nmap -p 3389 --script=rdp-enum-encryption,rdp-vuln-ms12-020 -Pn {} 2>/dev/null", target),
                &scans.join("rdp_check.txt"), 30
            ).await.unwrap_or_default();
            if out.contains("VULNERABLE") || out.contains("ms12-020") {
                findings.push(Finding {
                    severity: FindingSeverity::Critical,
                    category: "rdp-vuln".into(),
                    title: "RDP MS12-020 vulnerability detected".into(),
                    detail: out.lines().find(|l| l.contains("VULN") || l.contains("ms12")).unwrap_or("").trim().to_string(),
                    tool: "nmap".into(),
                });
            }
        }
        if avail("crackmapexec") && cfg.creds.has_auth() {
            sh(&format!("crackmapexec rdp {} -u {} -p '{}' 2>/dev/null",
                target, cfg.creds.user(), cfg.creds.pass()),
                &scans.join("cme_rdp.txt"), 30).await.ok();
        }
    }

    // CrackMapExec SMB/WinRM auth
    if cfg.creds.has_auth() && avail("crackmapexec") {
        let out = sh(
            &format!("crackmapexec smb {} -u {} -p '{}' 2>/dev/null",
                target, cfg.creds.user(), cfg.creds.pass()),
            &scans.join("cme_smb_auth.txt"), 60
        ).await.unwrap_or_default();
        if out.contains("Pwn3d!") {
            findings.push(Finding {
                severity: FindingSeverity::Critical,
                category: "auth".into(),
                title: "Local admin access confirmed via SMB".into(),
                detail: out.lines().find(|l| l.contains("Pwn3d!")).unwrap_or("").trim().to_string(),
                tool: "crackmapexec".into(),
            });
        }
    }

    Ok(findings)
}
