
use anyhow::{Context, Result};
use std::path::Path;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

pub async fn run(cmd: &str, args: &[&str], out: &Path, timeout_secs: u64) -> Result<String> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn failed: {}", cmd))?;

    let output = if timeout_secs > 0 {
        let fut = child.wait_with_output();
        match timeout(Duration::from_secs(timeout_secs), fut).await {
            Ok(r)  => r?,
            Err(_) => {
                let m = format!("[TIMEOUT] {} > {}s\n", cmd, timeout_secs);
                let _ = tokio::fs::write(out, &m).await;
                return Ok(m);
            }
        }
    } else { child.wait_with_output().await? };

    let mut out_str = String::from_utf8_lossy(&output.stdout).to_string();
    let err = String::from_utf8_lossy(&output.stderr).to_string();
    if !err.is_empty() { out_str.push_str("\n[STDERR]\n"); out_str.push_str(&err); }

    if let Some(p) = out.parent() { tokio::fs::create_dir_all(p).await.ok(); }
    tokio::fs::write(out, &out_str).await.ok();
    Ok(out_str)
}

pub async fn sh(cmd: &str, out: &Path, timeout_secs: u64) -> Result<String> {
    run("bash", &["-c", cmd], out, timeout_secs).await
}

pub fn avail(tool: &str) -> bool { which::which(tool).is_ok() }
