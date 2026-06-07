use std::collections::HashMap;
use crate::config::AgentConfig;

pub async fn check_and_report(cfg: &AgentConfig) -> Result<(), Box<dyn std::error::Error>> {
    let settings = collect_settings();

    let device_id = cfg.device_id.as_deref().ok_or("not enrolled")?;
    let token = cfg.device_token.as_deref().ok_or("no token")?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(cfg.insecure_skip_verify)
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let url = format!("{}/api/devices/{}/compliance-check", cfg.server_url, device_id);
    client.post(&url)
        .bearer_auth(token)
        .json(&serde_json::json!({"settings": settings, "platform": std::env::consts::OS}))
        .send().await?;

    Ok(())
}

fn collect_settings() -> HashMap<String, String> {
    let mut s = HashMap::new();
    s.insert("platform".to_string(), std::env::consts::OS.to_string());

    #[cfg(target_os = "linux")]
    collect_linux(&mut s);

    #[cfg(target_os = "macos")]
    collect_macos(&mut s);

    #[cfg(target_os = "windows")]
    collect_windows(&mut s);

    s
}

#[cfg(target_os = "linux")]
fn collect_linux(s: &mut HashMap<String, String>) {
    let ufw = std::process::Command::new("ufw").arg("status").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("active"))
        .unwrap_or(false);
    s.insert("firewall_enabled".to_string(), ufw.to_string());

    let luks = std::process::Command::new("lsblk").args(["-o", "TYPE"]).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("crypt"))
        .unwrap_or(false);
    s.insert("full_disk_encryption".to_string(), luks.to_string());
}

#[cfg(target_os = "macos")]
fn collect_macos(s: &mut HashMap<String, String>) {
    let fv = std::process::Command::new("fdesetup").arg("status").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("On"))
        .unwrap_or(false);
    s.insert("filevault_enabled".to_string(), fv.to_string());
}

#[cfg(target_os = "windows")]
fn collect_windows(s: &mut HashMap<String, String>) {
    // Read from Windows Registry
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey("SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU") {
            let no_auto: u32 = key.get_value("NoAutoUpdate").unwrap_or(0);
            s.insert("auto_update_enabled".to_string(), (no_auto == 0).to_string());
        }
    }
    s.insert("platform".to_string(), "windows".to_string());
}
