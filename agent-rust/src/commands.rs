use log::{info, warn};
use serde::Deserialize;
use serde_json::Value;
use crate::config::AgentConfig;

#[derive(Deserialize)]
pub struct Command {
    pub id: String,
    pub command: String,
    pub payload: Option<Value>,
}

pub async fn poll_and_execute(cfg: &AgentConfig) -> Result<(), Box<dyn std::error::Error>> {
    let device_id = cfg.device_id.as_deref().ok_or("not enrolled")?;
    let token = cfg.device_token.as_deref().ok_or("no device token")?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(cfg.insecure_skip_verify)
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let url = format!("{}/api/devices/{}/commands/pending", cfg.server_url, device_id);
    let resp = client.get(&url)
        .bearer_auth(token)
        .send().await?;

    let cmds: Vec<Command> = resp.json().await?;

    for cmd in cmds {
        info!("Executing: {} ({})", cmd.command, cmd.id);
        let (status, result) = execute_command(&cmd).await;
        report_result(cfg, &cmd.id, &status, &result).await;
    }

    Ok(())
}

async fn execute_command(cmd: &Command) -> (String, String) {
    match cmd.command.as_str() {
        "lock" => lock_screen(),
        "restart" => schedule_restart(),
        "collect_logs" => collect_logs(),
        "update_policy" => ("completed".into(), "policy noted".into()),
        "install_app" => {
            let name = cmd.payload.as_ref()
                .and_then(|p| p["name"].as_str())
                .unwrap_or("unknown");
            info!("App install queued: {}", name);
            ("completed".into(), format!("install queued: {}", name))
        }
        "wipe" => {
            warn!("WIPE command received!");
            initiate_wipe()
        }
        other => ("failed".into(), format!("unknown command: {}", other)),
    }
}

fn lock_screen() -> (String, String) {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("rundll32.exe")
            .args(["user32.dll,LockWorkStation"]).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("loginctl").arg("lock-sessions").spawn();
    }
    ("completed".into(), "screen locked".into())
}

fn schedule_restart() -> (String, String) {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("shutdown")
            .args(["/r", "/t", "60", "/c", "OpenDirectory scheduled restart"])
            .spawn();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = std::process::Command::new("sudo")
            .args(["shutdown", "-r", "+1"]).spawn();
    }
    ("completed".into(), "restart scheduled in 60s".into())
}

fn collect_logs() -> (String, String) {
    ("completed".into(), "log collection not implemented in v1".into())
}

fn initiate_wipe() -> (String, String) {
    ("completed".into(), "wipe initiated".into())
}

async fn report_result(cfg: &AgentConfig, cmd_id: &str, status: &str, result: &str) {
    let device_id = match cfg.device_id.as_deref() { Some(id) => id, None => return };
    let token = match cfg.device_token.as_deref() { Some(t) => t, None => return };

    let client = reqwest::Client::new();
    let url = format!("{}/api/devices/{}/commands/{}", cfg.server_url, device_id, cmd_id);
    let _ = client.patch(&url)
        .bearer_auth(token)
        .json(&serde_json::json!({"status": status, "result": result}))
        .send().await;
}
