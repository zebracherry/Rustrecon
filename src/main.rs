mod engine;
mod modules;
mod report;

use anyhow::Result;
use clap::Parser;
use colored::*;
use engine::{Config, Runner};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "rustrecon",
    about = "OSCP async recon — auto-classifies Linux / Windows / AD targets",
    long_about = None,
    version = "0.1.0",
    after_help = "EXAMPLES:
  rustrecon 10.10.10.1
  rustrecon 10.10.10.1 -d corp.local -u admin -p Password1
  rustrecon 10.10.10.1 --type ad -d corp.local
  rustrecon -t targets.txt -o /tmp/results -m 3
  rustrecon 10.10.10.1 --only web,smb
  rustrecon 10.10.10.1 --ports 80,443,8080"
)]
pub struct Cli {
    /// Target IP address or hostname
    #[arg(required_unless_present = "target_file")]
    pub target: Option<String>,
    /// File containing one target per line
    #[arg(short = 't', long = "targets", value_name = "FILE")]
    pub target_file: Option<String>,
    /// Output directory for results
    #[arg(short = 'o', long = "output", default_value = "results", value_name = "DIR")]
    pub output: String,
    /// Domain name for AD/DNS (e.g. corp.local)
    #[arg(short = 'd', long = "domain", value_name = "DOMAIN")]
    pub domain: Option<String>,
    /// Username for authenticated scans
    #[arg(short = 'u', long = "username", value_name = "USER")]
    pub username: Option<String>,
    /// Password
    #[arg(short = 'p', long = "password", value_name = "PASS")]
    pub password: Option<String>,
    /// NTLM hash for pass-the-hash (LM:NT)
    #[arg(long = "hash", value_name = "LM:NT")]
    pub hash: Option<String>,
    /// Force target type: auto, linux, windows, ad
    #[arg(long = "type", default_value = "auto", value_name = "TYPE")]
    pub target_type: String,
    /// Max concurrent scans
    #[arg(short = 'm', long = "max-scans", default_value_t = 5, value_name = "N")]
    pub max_scans: usize,
    /// Skip portscan — enumerate only these ports (e.g. 80,443,22)
    #[arg(long = "ports", value_name = "PORTS")]
    pub ports: Option<String>,
    /// Run only specific phases: portscan,web,smb,windows,linux,ad,network
    #[arg(long = "only", value_name = "PHASES")]
    pub only: Option<String>,
    /// Username wordlist for brute-force hints
    #[arg(long = "userlist",
          default_value = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
          value_name = "FILE")]
    pub userlist: String,
    /// Password wordlist for brute-force hints
    #[arg(long = "passlist",
          default_value = "/usr/share/seclists/Passwords/darkweb2017-top100.txt",
          value_name = "FILE")]
    pub passlist: String,
    /// Verbose output (-v = commands, -vv = raw output)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    banner();

    let mut targets: Vec<String> = Vec::new();
    if let Some(t) = &cli.target { targets.push(t.clone()); }
    if let Some(f) = &cli.target_file {
        for line in std::fs::read_to_string(f)?.lines() {
            let l = line.trim();
            if !l.is_empty() && !l.starts_with('#') { targets.push(l.to_string()); }
        }
    }
    if targets.is_empty() {
        eprintln!("{}", "[!] No targets provided.".red().bold());
        std::process::exit(1);
    }

    let cfg = Config::from_cli(&cli);
    Runner::new(cfg).run(targets).await
}

fn banner() {
    println!("{}", r"
  ____            _   ____
 |  _ \ _   _ ___| |_|  _ \ ___  ___ ___  _ __
 | |_) | | | / __| __| |_) / _ \/ __/ _ \| '_ \
 |  _ <| |_| \__ \ |_|  _ <  __/ (_| (_) | | | |
 |_| \_\\__,_|___/\__|_| \_\___|\___\___/|_| |_|
".cyan().bold());
    println!("  {}  v0.1.0  OSCP async recon — Linux / Windows / Active Directory\n",
        "▶".yellow().bold());

    // Legal disclaimer — always shown
    let line = "─".repeat(68);
    println!("  {}", line.yellow());
    println!("  {}  {}",
        "⚠".yellow().bold(),
        "For authorised testing only.".yellow().bold());
    println!("  {}  {}",
        " ".normal(),
        "No auto-exploitation — stays within OSCP exam rules.".yellow());
    println!("  {}\n", line.yellow());
}
