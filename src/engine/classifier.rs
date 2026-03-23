
use super::{Config, TypeHint};
use crate::engine::types::{Port, TargetType};

pub fn classify(ports: &[Port], nmap_raw: &str, cfg: &Config) -> TargetType {
    match cfg.hint {
        TypeHint::Linux   => return TargetType::Linux,
        TypeHint::Windows => return TargetType::Windows,
        TypeHint::AD      => return TargetType::AD,
        TypeHint::Auto    => {}
    }
    let nums: Vec<u16> = ports.iter().map(|p| p.number).collect();
    let raw = nmap_raw.to_lowercase();

    // AD = Kerberos + LDAP
    if nums.contains(&88) && (nums.contains(&389) || nums.contains(&636)) {
        return TargetType::AD;
    }

    let mut win = 0i32;
    let mut lnx = 0i32;

    for n in &nums {
        match n {
            135|139|445|3389|5985|5986 => win += 2,
            88|389|636|3268|3269        => win += 3,
            22|111|2049                 => lnx += 2,
            _                           => {}
        }
    }
    for kw in &["windows","microsoft","iis","netbios","ms-wbt","rdp","winrm"] {
        if raw.contains(kw) { win += 1; }
    }
    for kw in &["linux","ubuntu","debian","openssh","apache","nginx","nfs","rpcbind"] {
        if raw.contains(kw) { lnx += 1; }
    }
    for p in ports {
        let s = p.service.to_lowercase();
        if s.contains("microsoft") || s.contains("netbios") { win += 1; }
        if s.contains("openssh") || s.contains("nfs")       { lnx += 1; }
    }

    if win > lnx   { TargetType::Windows }
    else if lnx > 0 { TargetType::Linux }
    else            { TargetType::Unknown }
}
