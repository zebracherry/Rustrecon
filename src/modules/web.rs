
use crate::engine::{Config, Finding, FindingSeverity};
use crate::engine::executor::{sh, avail};
use anyhow::Result;
use colored::*;
use std::path::Path;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Instant;
use tokio::time::{sleep, Duration};

// ── Progress ticker ────────────────────────────────────────────────────────────
// Spawns a background task that prints "  [tool] elapsed Xs..." every 5s
// until the done flag is set. Gives the user clear proof the tool is running.
struct Ticker {
    done: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<()>,
}
impl Ticker {
    fn start(tool: &str, target: &str, extra: &str) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let done2 = Arc::clone(&done);
        let label = format!("[{}] {} on {}", tool.cyan().bold(), extra, target.yellow());
        let handle = tokio::spawn(async move {
            let start = Instant::now();
            let frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"];
            let mut i = 0usize;
            loop {
                if done2.load(Ordering::Relaxed) { break; }
                let elapsed = start.elapsed().as_secs();
                // eprint! so it stays on same line, \r rewinds
                eprint!("\r    {} {} — {}s elapsed   ",
                    frames[i % frames.len()].cyan(),
                    label,
                    elapsed);
                i += 1;
                sleep(Duration::from_millis(500)).await;
            }
            let elapsed = start.elapsed().as_secs();
            // Clear the line, print done
            eprintln!("\r    {} {} — done in {}s{}",
                "✓".green().bold(), label, elapsed,
                " ".repeat(10));
        });
        Self { done, handle }
    }
    async fn finish(self) {
        self.done.store(true, Ordering::Relaxed);
        let _ = self.handle.await;
    }
}

// ── Tool definitions ──────────────────────────────────────────────────────────
// Each tool has a name, timeout, and whether it should show progress
struct WebTool {
    name: &'static str,
    timeout: u64,
}
const TOOLS: &[WebTool] = &[
    WebTool { name: "curl",        timeout: 30  },
    WebTool { name: "whatweb",     timeout: 60  },
    WebTool { name: "feroxbuster", timeout: 300 },
    WebTool { name: "nikto",       timeout: 300 },
    WebTool { name: "wpscan",      timeout: 180 },
    WebTool { name: "sslscan",     timeout: 60  },
    WebTool { name: "ffuf",        timeout: 120 },
];

pub async fn run(target: &str, cfg: &Config, base: &Path, ports: &[u16]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let scans = base.join("scans");
    let total_ports = ports.len();

    for (port_idx, &port) in ports.iter().enumerate() {
        let scheme = if port == 443 || port == 8443 { "https" } else { "http" };
        let url    = format!("{}://{}:{}", scheme, target, port);
        let tag    = format!("tcp{}", port);

        // Count available tools for this port
        let tool_names = ["curl","whatweb","feroxbuster","nikto","wpscan","sslscan","ffuf"];
        let avail_tools: Vec<&str> = tool_names.iter()
            .filter(|&&t| {
                if t == "sslscan" { (port == 443 || port == 8443) && avail(t) }
                else if t == "ffuf" { cfg.creds.domain.is_some() && avail(t) }
                else { avail(t) }
            })
            .copied().collect();
        let total_tools = avail_tools.len();

        println!("  {} [{}/{}] port {} — {} tool(s) queued",
            "→".yellow(), port_idx + 1, total_ports, port, total_tools);

        let mut tool_idx = 0usize;

        // ── 1. curl — headers (fast, always first) ────────────────────────────
        if avail("curl") {
            tool_idx += 1;
            progress_start(tool_idx, total_tools, "curl", "grabbing headers", &url);
            let tick = Ticker::start("curl", target, &format!("port {}", port));
            let cmd = format!("curl -sk -I -L --max-time 10 -A 'Mozilla/5.0' {} 2>/dev/null", url);
            let out = sh(&cmd, &scans.join(format!("curl_headers_{tag}.txt")), 30)
                .await.unwrap_or_default();
            tick.finish().await;
            for line in out.lines() {
                let low = line.to_lowercase();
                if low.starts_with("server:") || low.starts_with("x-powered-by:") {
                    findings.push(Finding {
                        severity: FindingSeverity::Info,
                        category: "web-header".into(),
                        title: format!("Header disclosure: {}", line.trim()),
                        detail: line.trim().to_string(),
                        tool: "curl".into(),
                    });
                }
                if low.contains("www-authenticate") || low.contains("basic realm") {
                    findings.push(Finding {
                        severity: FindingSeverity::Medium,
                        category: "web-auth".into(),
                        title: "HTTP Basic Auth detected".into(),
                        detail: line.trim().to_string(),
                        tool: "curl".into(),
                    });
                }
            }
        }

        // ── 2. whatweb — tech fingerprint ─────────────────────────────────────
        if avail("whatweb") {
            tool_idx += 1;
            progress_start(tool_idx, total_tools, "whatweb", "fingerprinting tech stack", &url);
            let tick = Ticker::start("whatweb", target, &format!("port {}", port));
            let cmd = format!("whatweb -a 3 --colour=never {} 2>/dev/null", url);
            let out = sh(&cmd, &scans.join(format!("whatweb_{tag}.txt")), 60)
                .await.unwrap_or_default();
            tick.finish().await;
            if !out.is_empty() {
                findings.push(Finding {
                    severity: FindingSeverity::Info,
                    category: "web-tech".into(),
                    title: format!("Web technologies on {}", url),
                    detail: out.lines().next().unwrap_or("").chars().take(300).collect(),
                    tool: "whatweb".into(),
                });
            }
        }

        // ── 3. feroxbuster — directory/file brute ─────────────────────────────
        if avail("feroxbuster") {
            tool_idx += 1;
            let wl = if std::path::Path::new(
                "/usr/share/seclists/Discovery/Web-Content/common.txt").exists() {
                "/usr/share/seclists/Discovery/Web-Content/common.txt"
            } else {
                "/usr/share/wordlists/dirb/common.txt"
            };
            progress_start(tool_idx, total_tools, "feroxbuster", "directory brute force", &url);
            let tick = Ticker::start("feroxbuster", target, &format!("port {} (this takes a few minutes)", port));
            let out_file = scans.join(format!("ferox_{tag}.txt"));
            let cmd = format!(
                "feroxbuster -u {url} -w {wl} -x php,asp,aspx,txt,html,jsp \
                 -t 30 -o {} --no-state --silent 2>/dev/null",
                out_file.display());
            sh(&cmd, &scans.join(format!("ferox_{tag}_run.log")), 300).await.ok();
            tick.finish().await;
            if let Ok(content) = tokio::fs::read_to_string(&out_file).await {
                let mut found = 0u32;
                for line in content.lines() {
                    if line.contains("200") || line.contains("301") || line.contains("302") || line.contains("403") {
                        let path = line.split_whitespace().last().unwrap_or("").to_string();
                        if !path.is_empty() && path.starts_with('/') {
                            found += 1;
                            let sev = if path.to_lowercase().contains("admin")
                                || path.to_lowercase().contains("backup")
                                || path.to_lowercase().contains("config")
                            { FindingSeverity::Medium } else { FindingSeverity::Info };
                            findings.push(Finding {
                                severity: sev,
                                category: "web-path".into(),
                                title: format!("Found: {}{}", url, path),
                                detail: line.chars().take(200).collect(),
                                tool: "feroxbuster".into(),
                            });
                        }
                    }
                }
                println!("    {} feroxbuster: {} path(s) found", "→".cyan(), found);
            }
        }

        // ── 4. nikto — vulnerability scanner ─────────────────────────────────
        if avail("nikto") {
            tool_idx += 1;
            progress_start(tool_idx, total_tools, "nikto", "vulnerability scan", &url);
            let tick = Ticker::start("nikto", target, &format!("port {} (this takes a few minutes)", port));
            let cmd = format!("nikto -h {url} -nointeractive -Format txt 2>/dev/null");
            let out = sh(&cmd, &scans.join(format!("nikto_{tag}.txt")), 300)
                .await.unwrap_or_default();
            tick.finish().await;
            let mut found = 0u32;
            for line in out.lines() {
                if line.starts_with("+ ") && !line.contains("headers") && !line.contains("No CGI") {
                    found += 1;
                    let sev = if line.to_lowercase().contains("vuln")
                        || line.contains("CVE")
                        || line.contains("XSS")
                        || line.contains("injection")
                    { FindingSeverity::High } else { FindingSeverity::Medium };
                    findings.push(Finding {
                        severity: sev,
                        category: "web-vuln".into(),
                        title: format!("Nikto [{}]: {}", port, &line[2..].chars().take(80).collect::<String>()),
                        detail: line.chars().take(300).collect(),
                        tool: "nikto".into(),
                    });
                }
            }
            println!("    {} nikto: {} finding(s)", "→".cyan(), found);
        }

        // ── 5. wpscan — WordPress detection ──────────────────────────────────
        if avail("wpscan") {
            tool_idx += 1;
            progress_start(tool_idx, total_tools, "wpscan", "WordPress scan", &url);
            let tick = Ticker::start("wpscan", target, &format!("port {}", port));
            let cmd = format!(
                "wpscan --url {url} --no-banner --disable-tls-checks \
                 --enumerate p,t,u --format cli-no-colour 2>/dev/null");
            let out = sh(&cmd, &scans.join(format!("wpscan_{tag}.txt")), 180)
                .await.unwrap_or_default();
            tick.finish().await;
            if out.contains("WordPress") || out.contains("wp-content") {
                findings.push(Finding {
                    severity: FindingSeverity::Medium,
                    category: "cms".into(),
                    title: format!("WordPress detected on {}", url),
                    detail: out.lines()
                        .find(|l| l.contains("WordPress") || l.contains("version"))
                        .unwrap_or("").trim().to_string(),
                    tool: "wpscan".into(),
                });
                // Flag outdated plugins/themes
                for line in out.lines() {
                    if line.contains("[!]") && (line.contains("outdated") || line.contains("vulnerabilit")) {
                        findings.push(Finding {
                            severity: FindingSeverity::High,
                            category: "cms-vuln".into(),
                            title: format!("WPScan: {}", line.trim().chars().take(100).collect::<String>()),
                            detail: line.trim().to_string(),
                            tool: "wpscan".into(),
                        });
                    }
                }
            } else {
                println!("    {} wpscan: WordPress not detected", "→".cyan());
            }
        }

        // ── 6. sslscan — HTTPS cipher/cert check ─────────────────────────────
        if (port == 443 || port == 8443) && avail("sslscan") {
            tool_idx += 1;
            progress_start(tool_idx, total_tools, "sslscan", "TLS/SSL audit", &url);
            let tick = Ticker::start("sslscan", target, &format!("port {}", port));
            let cmd = format!("sslscan --no-colour {}:{} 2>/dev/null", target, port);
            let out = sh(&cmd, &scans.join(format!("sslscan_{tag}.txt")), 60)
                .await.unwrap_or_default();
            tick.finish().await;
            for line in out.lines() {
                let low = line.to_lowercase();
                if low.contains("sslv3") || low.contains("tlsv1.0") || low.contains("tlsv1.1") {
                    findings.push(Finding {
                        severity: FindingSeverity::High,
                        category: "tls-weak".into(),
                        title: format!("Weak protocol enabled: {}", line.trim()),
                        detail: line.trim().to_string(),
                        tool: "sslscan".into(),
                    });
                }
                if low.contains("heartbleed") && low.contains("vulnerable") {
                    findings.push(Finding {
                        severity: FindingSeverity::Critical,
                        category: "tls-vuln".into(),
                        title: "HEARTBLEED vulnerability detected!".into(),
                        detail: line.trim().to_string(),
                        tool: "sslscan".into(),
                    });
                }
            }
        }

        // ── 7. ffuf — virtual host enumeration (if domain known) ──────────────
        if let Some(domain) = &cfg.creds.domain {
            if avail("ffuf") {
                tool_idx += 1;
                progress_start(tool_idx, total_tools, "ffuf", "vhost enumeration", &url);
                let tick = Ticker::start("ffuf", target, &format!("vhosts for {}", domain));
                let wl = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt";
                let cmd = format!(
                    "ffuf -u {url} -H 'Host: FUZZ.{domain}' -w {wl} \
                     -mc 200,301,302,403 -fs 0 -t 30 -o {} -of csv 2>/dev/null",
                    scans.join(format!("ffuf_vhosts_{tag}.txt")).display());
                let out = sh(&cmd, &scans.join(format!("ffuf_vhosts_{tag}_run.log")), 120)
                    .await.unwrap_or_default();
                tick.finish().await;
                // Count results
                let hits = out.lines().filter(|l| !l.starts_with("FUZZ") && !l.is_empty()).count();
                if hits > 0 {
                    println!("    {} ffuf: {} vhost(s) found", "→".cyan(), hits);
                }
            }
        }

        println!("  {} port {} web enum complete — {} finding(s) so far",
            "✓".green().bold(), port, findings.len());
    }

    Ok(findings)
}

fn progress_start(current: usize, total: usize, tool: &str, action: &str, url: &str) {
    // Draw a simple ASCII progress bar
    let filled  = (current * 20) / total;
    let empty   = 20 - filled;
    let bar: String = format!("[{}{}]",
        "█".repeat(filled).green().to_string(),
        "░".repeat(empty).bright_black().to_string(),
    );
    println!("  {} {}/{} {} {} — {}",
        bar,
        current, total,
        tool.cyan().bold(),
        action,
        url.bright_black(),
    );
}
