use log::info;
use serde::{Deserialize, Serialize};
use crate::config::AgentConfig;

#[derive(Serialize)]
struct EnrollRequest {
    token: String,
    platform: String,
    hostname: String,
    os: String,
    serial: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnrollResponse {
    device_id: String,
    device_token: String,
}

pub async fn enroll(cfg: &mut AgentConfig) -> Result<(), Box<dyn std::error::Error>> {
    let token = cfg.enrollment_token.clone()
        .ok_or("OD_ENROLLMENT_TOKEN not set")?;

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(cfg.insecure_skip_verify)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let payload = EnrollRequest {
        token,
        platform: std::env::consts::OS.to_string(),
        hostname: hostname.clone(),
        os: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
        serial: "unknown".to_string(),
    };

    let url = format!("{}/api/enrollment/register", cfg.server_url);
    let resp = client.post(&url)
        .json(&payload)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(format!("Enrollment failed: HTTP {}", resp.status()).into());
    }

    let result: EnrollResponse = resp.json().await?;
    cfg.device_id = Some(result.device_id.clone());
    cfg.device_token = Some(result.device_token);
    cfg.save()?;

    info!("Enrolled successfully. Device ID: {}", result.device_id);
    Ok(())
}
