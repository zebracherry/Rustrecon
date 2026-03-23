
use crate::engine::{ScanResult, FindingSeverity};
use anyhow::Result;
use std::path::Path;

pub async fn write_html(res: &ScanResult, base: &Path) -> Result<()> {
    let html = render_html(res);
    let path = base.join("report").join("report.html");
    tokio::fs::create_dir_all(path.parent().unwrap()).await?;
    tokio::fs::write(&path, html).await?;
    Ok(())
}

pub async fn write_findings_md(res: &ScanResult, base: &Path) -> Result<()> {
    let mut md = format!("# Findings — {}\n\n**Target type:** {}  \n**Scan started:** {}  \n**Finished:** {}\n\n",
        res.target, res.target_type.label(),
        res.started, res.finished.as_deref().unwrap_or("in progress"));

    md.push_str(&format!("## Open Ports ({})\n\n| Port | Proto | Service | Version |\n|------|-------|---------|----------|\n", res.ports.len()));
    for p in &res.ports {
        md.push_str(&format!("| {} | {} | {} | {} |\n",
            p.number, p.proto, p.service, p.version.as_deref().unwrap_or("")));
    }
    md.push('\n');

    for sev in &[FindingSeverity::Critical, FindingSeverity::High,
                 FindingSeverity::Medium, FindingSeverity::Low, FindingSeverity::Info] {
        let hits: Vec<_> = res.findings.iter().filter(|f| &f.severity == sev).collect();
        if hits.is_empty() { continue; }
        md.push_str(&format!("## {} ({})\n\n", sev.label(), hits.len()));
        for f in hits {
            md.push_str(&format!("### {}\n- **Category:** {}  \n- **Tool:** {}  \n- {}\n\n",
                f.title, f.category, f.tool, f.detail));
        }
    }
    tokio::fs::write(base.join("report").join("findings.md"), md).await?;
    Ok(())
}

pub async fn write_manual_cmds(res: &ScanResult, base: &Path) -> Result<()> {
    let content = format!(
        "# Manual Commands — {}\n# Generated: {}\n# Run these manually after reviewing automated results\n\n{}\n",
        res.target,
        res.started,
        res.manual_cmds.join("\n\n")
    );
    tokio::fs::write(base.join("scans").join("_manual_commands.txt"), content).await?;
    Ok(())
}

pub async fn write_cmd_log(res: &ScanResult, base: &Path) -> Result<()> {
    let content = format!(
        "# Commands run against {}\n# {}\n\n{}\n",
        res.target, res.started, res.cmd_log.join("\n")
    );
    tokio::fs::write(base.join("scans").join("_commands.log"), content).await?;
    Ok(())
}

fn render_html(res: &ScanResult) -> String {
    let crit = res.findings.iter().filter(|f| f.severity==FindingSeverity::Critical).count();
    let high = res.findings.iter().filter(|f| f.severity==FindingSeverity::High).count();
    let med  = res.findings.iter().filter(|f| f.severity==FindingSeverity::Medium).count();

    let ports_html: String = res.ports.iter().map(|p| format!(
        "<tr><td class='port'>{}</td><td>{}</td><td class='service'>{}</td><td>{}</td></tr>",
        p.number, p.proto, p.service, p.version.as_deref().unwrap_or("")
    )).collect();

    let findings_html: String = res.findings.iter().map(|f| {
        let cls = match f.severity {
            FindingSeverity::Critical => "critical",
            FindingSeverity::High     => "high",
            FindingSeverity::Medium   => "medium",
            FindingSeverity::Low      => "low",
            FindingSeverity::Info     => "info",
        };
        format!(r#"<div class="finding {cls}">
  <div class="finding-header">
    <span class="badge {cls}">{}</span>
    <span class="finding-title">{}</span>
    <span class="tool-badge">{}</span>
  </div>
  <div class="finding-detail">{}</div>
</div>"#,
            f.severity.label(), escape_html(&f.title), escape_html(&f.tool), escape_html(&f.detail))
    }).collect();

    let manual_html: String = res.manual_cmds.iter().map(|cmd| {
        format!("<pre class='cmd'>{}</pre>", escape_html(cmd))
    }).collect();

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RustRecon — {target}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}}
header{{background:linear-gradient(135deg,#161b22,#1f2937);padding:24px 40px;border-bottom:1px solid #30363d}}
header h1{{font-size:1.8rem;color:#58a6ff;letter-spacing:-0.5px}}
header .meta{{color:#8b949e;font-size:.9rem;margin-top:6px}}
.type-badge{{display:inline-block;padding:3px 12px;border-radius:20px;font-size:.8rem;font-weight:600;margin-left:10px;
  background:{type_bg};color:{type_fg}}}
main{{max-width:1200px;margin:0 auto;padding:32px 40px}}
.summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:32px}}
.summary-card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;text-align:center}}
.summary-card .num{{font-size:2.2rem;font-weight:700;line-height:1}}
.summary-card .label{{font-size:.8rem;color:#8b949e;margin-top:6px;text-transform:uppercase;letter-spacing:.5px}}
.summary-card.critical{{border-color:#f85149}}.summary-card.critical .num{{color:#f85149}}
.summary-card.high{{border-color:#e3b341}}.summary-card.high .num{{color:#e3b341}}
.summary-card.medium{{border-color:#d29922}}.summary-card.medium .num{{color:#d29922}}
.summary-card.ports .num{{color:#58a6ff}}
h2{{font-size:1.2rem;color:#e6edf3;margin:32px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d}}
table{{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;border:1px solid #30363d}}
th{{background:#21262d;padding:10px 14px;text-align:left;font-size:.8rem;text-transform:uppercase;
   letter-spacing:.5px;color:#8b949e;border-bottom:1px solid #30363d}}
td{{padding:10px 14px;border-bottom:1px solid #21262d;font-size:.9rem}}
tr:last-child td{{border-bottom:none}}
td.port{{font-family:monospace;font-weight:700;color:#58a6ff}}
td.service{{color:#7ee787}}
.finding{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:12px;overflow:hidden}}
.finding-header{{padding:12px 16px;display:flex;align-items:center;gap:12px;background:#1c2128}}
.badge{{padding:3px 10px;border-radius:4px;font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px}}
.badge.critical{{background:#3d1c1c;color:#f85149;border:1px solid #f85149}}
.badge.high{{background:#2d2008;color:#e3b341;border:1px solid #e3b341}}
.badge.medium{{background:#26200a;color:#d29922;border:1px solid #d29922}}
.badge.low{{background:#0d2b12;color:#3fb950;border:1px solid #3fb950}}
.badge.info{{background:#0c1d2e;color:#58a6ff;border:1px solid #58a6ff}}
.finding-title{{flex:1;font-weight:600;font-size:.95rem}}
.tool-badge{{font-size:.75rem;color:#8b949e;background:#21262d;padding:2px 8px;border-radius:4px}}
.finding-detail{{padding:10px 16px;font-size:.85rem;color:#8b949e;font-family:monospace}}
pre.cmd{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:14px 16px;
  font-family:'Cascadia Code',monospace;font-size:.85rem;color:#7ee787;margin-bottom:10px;overflow-x:auto;white-space:pre-wrap}}
footer{{text-align:center;padding:24px;color:#484f58;font-size:.8rem;border-top:1px solid #30363d;margin-top:48px}}
</style>
</head>
<body>
<header>
  <h1>&#128270; RustRecon Report
    <span class="type-badge">{target_type}</span>
  </h1>
  <div class="meta">
    Target: <strong style="color:#e6edf3">{target}</strong> &nbsp;|&nbsp;
    Started: {started} &nbsp;|&nbsp;
    Finished: {finished}
  </div>
</header>
<main>
<div class="summary-grid">
  <div class="summary-card ports"><div class="num">{port_count}</div><div class="label">Open Ports</div></div>
  <div class="summary-card critical"><div class="num">{crit}</div><div class="label">Critical</div></div>
  <div class="summary-card high"><div class="num">{high}</div><div class="label">High</div></div>
  <div class="summary-card medium"><div class="num">{med}</div><div class="label">Medium</div></div>
</div>

<h2>&#127760; Open Ports</h2>
<table>
<thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr></thead>
<tbody>{ports_html}</tbody>
</table>

<h2>&#9888; Findings ({total_findings})</h2>
{findings_html}

<h2>&#128196; Manual Commands</h2>
{manual_html}

</main>
<footer>Generated by RustRecon v0.1.0 &mdash; For authorised testing only</footer>
</body>
</html>"#,
        target       = escape_html(&res.target),
        target_type  = res.target_type.label(),
        type_bg      = match res.target_type {
            crate::engine::TargetType::Linux   => "#0d2b12",
            crate::engine::TargetType::Windows => "#0c1d2e",
            crate::engine::TargetType::AD      => "#2d0f2d",
            _                                  => "#1c1c1c",
        },
        type_fg      = match res.target_type {
            crate::engine::TargetType::Linux   => "#3fb950",
            crate::engine::TargetType::Windows => "#58a6ff",
            crate::engine::TargetType::AD      => "#d2a8ff",
            _                                  => "#8b949e",
        },
        started      = res.started,
        finished     = res.finished.as_deref().unwrap_or("in progress"),
        port_count   = res.ports.len(),
        crit = crit, high = high, med = med,
        total_findings = res.findings.len(),
        ports_html = ports_html, findings_html = findings_html, manual_html = manual_html,
    )
}

fn escape_html(s: &str) -> String {
    s.replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;").replace('"',"&quot;")
}
