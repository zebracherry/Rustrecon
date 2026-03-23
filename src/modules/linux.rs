
use crate::engine::{Config, Finding, FindingSeverity};
use crate::engine::executor::{sh, avail};
use anyhow::Result;
use std::path::Path;

pub async fn run(target: &str, _cfg: &Config, base: &Path, ports: &[u16]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let scans = base.join("scans");

    // SSH version check
    if ports.contains(&22) && avail("nmap") {
        let out = sh(
            &format!("nmap -p 22 -sV --script=ssh2-enum-algos,ssh-auth-methods -Pn {} 2>/dev/null", target),
            &scans.join("ssh_enum.txt"), 30
        ).await.unwrap_or_default();
        if let Some(ver_line) = out.lines().find(|l| l.contains("ssh") && l.contains("OpenSSH")) {
            findings.push(Finding {
                severity: FindingSeverity::Info,
                category: "ssh-version".into(),
                title: format!("SSH version: {}", ver_line.trim()),
                detail: ver_line.trim().to_string(),
                tool: "nmap".into(),
            });
        }
        // Old OpenSSH versions
        if out.contains("OpenSSH") {
            for line in out.lines() {
                if line.contains("OpenSSH") {
                    let old_versions = ["4.","5.","6.","7.0","7.1","7.2","7.3","7.4"];
                    if old_versions.iter().any(|v| line.contains(v)) {
                        findings.push(Finding {
                            severity: FindingSeverity::Medium,
                            category: "ssh-version".into(),
                            title: "Potentially outdated OpenSSH version".into(),
                            detail: line.trim().to_string(),
                            tool: "nmap".into(),
                        });
                    }
                }
            }
        }
    }

    // NFS mounts — if port 2049 open
    if ports.contains(&2049) && avail("showmount") {
        let out = sh(&format!("showmount -e {} 2>/dev/null", target),
            &scans.join("nfs_mounts.txt"), 30).await.unwrap_or_default();
        for line in out.lines().skip(1) {
            if !line.trim().is_empty() {
                let world_accessible = line.contains("*") || line.contains("everyone") || line.ends_with("/");
                findings.push(Finding {
                    severity: if world_accessible { FindingSeverity::High } else { FindingSeverity::Medium },
                    category: "nfs".into(),
                    title: format!("NFS mount: {}", line.trim()),
                    detail: format!("Mount point exposed: {}", line.trim()),
                    tool: "showmount".into(),
                });
            }
        }
    }

    // rpcbind
    if ports.contains(&111) {
        sh(&format!("rpcinfo -p {} 2>/dev/null", target),
            &scans.join("rpcbind.txt"), 15).await.ok();
    }

    // Finger (79)
    if ports.contains(&79) && avail("finger") {
        let out = sh(&format!("finger @{} 2>/dev/null", target),
            &scans.join("finger.txt"), 15).await.unwrap_or_default();
        if !out.is_empty() {
            findings.push(Finding {
                severity: FindingSeverity::Medium,
                category: "finger".into(),
                title: "Finger service exposes user information".into(),
                detail: out.trim().chars().take(200).collect(),
                tool: "finger".into(),
            });
        }
    }

    Ok(findings)
}
