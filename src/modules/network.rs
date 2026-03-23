
use crate::engine::{Config, Finding, FindingSeverity};
use crate::engine::executor::{sh, avail};
use anyhow::Result;
use std::path::Path;

pub async fn run(target: &str, _cfg: &Config, base: &Path, ports: &[u16]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let scans = base.join("scans");

    // DNS (53)
    if ports.contains(&53) {
        if avail("dnsrecon") {
            let out = sh(&format!("dnsrecon -d {} -t axfr 2>/dev/null", target),
                &scans.join("dnsrecon.txt"), 60).await.unwrap_or_default();
            if out.contains("Zone Transfer") && out.contains("NS ") {
                findings.push(Finding {
                    severity: FindingSeverity::High,
                    category: "dns".into(),
                    title: "DNS zone transfer succeeded".into(),
                    detail: out.lines().take(5).collect::<Vec<_>>().join(" | "),
                    tool: "dnsrecon".into(),
                });
            }
        }
        if avail("dig") {
            sh(&format!("dig axfr @{} 2>/dev/null", target),
                &scans.join("dig_axfr.txt"), 30).await.ok();
        }
    }

    // SSH (22)
    if ports.contains(&22) && avail("nmap") {
        let out = sh(
            &format!("nmap -p 22 --script=ssh-auth-methods,ssh-hostkey,ssh2-enum-algos -Pn -T4 {} 2>/dev/null", target),
            &scans.join("nmap_ssh.txt"), 30
        ).await.unwrap_or_default();
        if out.contains("password") && out.contains("publickey") {
            findings.push(Finding {
                severity: FindingSeverity::Medium,
                category: "ssh".into(),
                title: "SSH password auth enabled".into(),
                detail: "SSH accepts both password and publickey authentication".into(),
                tool: "nmap-ssh-scripts".into(),
            });
        }
    }

    // FTP (21)
    if ports.contains(&21) {
        if avail("nmap") {
            let out = sh(
                &format!("nmap -p 21 --script=ftp-anon,ftp-bounce,ftp-syst -Pn {} 2>/dev/null", target),
                &scans.join("nmap_ftp.txt"), 30
            ).await.unwrap_or_default();
            if out.contains("Anonymous FTP login allowed") {
                findings.push(Finding {
                    severity: FindingSeverity::High,
                    category: "ftp".into(),
                    title: "FTP anonymous login allowed".into(),
                    detail: "FTP server permits anonymous access".into(),
                    tool: "nmap-ftp-scripts".into(),
                });
            }
        }
    }

    // SMTP (25, 587, 465)
    if ports.iter().any(|&p| p==25||p==587||p==465) {
        if avail("nmap") {
            sh(
                &format!("nmap -p 25,587,465 --script=smtp-commands,smtp-enum-users,smtp-open-relay -Pn {} 2>/dev/null", target),
                &scans.join("nmap_smtp.txt"), 60
            ).await.ok();
        }
    }

    // SNMP (161/162)
    if ports.contains(&161) {
        if avail("onesixtyone") {
            let wl = "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt";
            let out = sh(&format!("onesixtyone -c {} {} 2>/dev/null", wl, target),
                &scans.join("onesixtyone.txt"), 60).await.unwrap_or_default();
            if !out.is_empty() && !out.contains("Timeout") {
                findings.push(Finding {
                    severity: FindingSeverity::High,
                    category: "snmp".into(),
                    title: "SNMP community string found".into(),
                    detail: out.trim().chars().take(200).collect(),
                    tool: "onesixtyone".into(),
                });
                // Walk with first found community
                if let Some(community) = out.lines().next()
                    .and_then(|l| l.split('[').nth(1))
                    .and_then(|l| l.split(']').next())
                {
                    sh(&format!("snmpwalk -c {} -v1 {} 2>/dev/null", community, target),
                        &scans.join("snmpwalk.txt"), 120).await.ok();
                }
            }
        }
    }

    // NFS (2049)
    if ports.contains(&2049) {
        if avail("showmount") {
            let out = sh(&format!("showmount -e {} 2>/dev/null", target),
                &scans.join("showmount.txt"), 30).await.unwrap_or_default();
            for line in out.lines() {
                if line.contains("/") {
                    findings.push(Finding {
                        severity: FindingSeverity::High,
                        category: "nfs".into(),
                        title: format!("NFS export found: {}", line.trim()),
                        detail: line.trim().to_string(),
                        tool: "showmount".into(),
                    });
                }
            }
        }
    }

    // RPC (111)
    if ports.contains(&111) {
        sh(&format!("rpcinfo -p {} 2>/dev/null", target),
            &scans.join("rpcinfo.txt"), 30).await.ok();
    }

    // MySQL (3306)
    if ports.contains(&3306) {
        if avail("nmap") {
            sh(&format!("nmap -p 3306 --script=mysql-info,mysql-empty-password,mysql-databases -Pn {} 2>/dev/null", target),
                &scans.join("nmap_mysql.txt"), 30).await.ok();
        }
    }

    // MSSQL (1433)
    if ports.contains(&1433) {
        if avail("nmap") {
            sh(&format!("nmap -p 1433 --script=ms-sql-info,ms-sql-empty-password -Pn {} 2>/dev/null", target),
                &scans.join("nmap_mssql.txt"), 30).await.ok();
        }
    }

    // Redis (6379)
    if ports.contains(&6379) {
        if avail("redis-cli") {
            let out = sh(&format!("redis-cli -h {} info server 2>/dev/null", target),
                &scans.join("redis_info.txt"), 15).await.unwrap_or_default();
            if out.contains("redis_version") {
                findings.push(Finding {
                    severity: FindingSeverity::Critical,
                    category: "redis".into(),
                    title: "Redis unauthenticated access".into(),
                    detail: out.lines().next().unwrap_or("").trim().to_string(),
                    tool: "redis-cli".into(),
                });
            }
        }
    }

    // RPC null session (135)
    if ports.contains(&135) && avail("rpcclient") {
        sh(&format!("rpcclient -U '' -N {} -c 'enumdomusers' 2>/dev/null", target),
            &scans.join("rpcclient_users.txt"), 30).await.ok();
    }

    Ok(findings)
}
