use crate::config::AgentConfig;
use log::info;
use serde::{Deserialize, Serialize};

pub const VERSION: &str = "1.4.0";
pub fn client(cfg: &AgentConfig) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    let url = reqwest::Url::parse(&cfg.server_url)?;
    if url.scheme() != "https"
        && !(url.scheme() == "http"
            && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")))
    {
        return Err("HTTPS is required for device credentials".into());
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("Server URL must be an origin without credentials or a path".into());
    }
    if cfg.insecure_skip_verify {
        return Err("OD_INSECURE is unsupported; install the CA or set OD_CA_CERT".into());
    }
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(20));
    if let Some(path) = &cfg.ca_cert_path {
        builder =
            builder.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(path)?)?);
    }
    Ok(builder.build()?)
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    hostname: String,
    platform: String,
    architecture: String,
    os_version: String,
    agent_version: String,
}
pub fn report() -> Report {
    Report {
        hostname: hostname::get()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".into()),
        platform: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        os_version: os_version(),
        agent_version: VERSION.into(),
    }
}
fn os_version() -> String {
    #[cfg(target_os = "linux")]
    if let Ok(value) = std::fs::read_to_string("/etc/os-release") {
        if let Some(line) = value
            .lines()
            .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        {
            return line.trim_matches('"').chars().take(120).collect();
        }
    }
    #[cfg(target_os = "macos")]
    if let Ok(value) = std::process::Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output()
    {
        if value.status.success() {
            return String::from_utf8_lossy(&value.stdout)
                .trim()
                .chars()
                .take(120)
                .collect();
        }
    }
    format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EnrollResponse {
    schema_version: u8,
    agent_protocol: u8,
    device_id: String,
    device_token: String,
    credential_expires_at: String,
}
fn device_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .map(|id| id.to_string() == value)
        .unwrap_or(false)
}
fn token(value: &str, prefix: &str) -> bool {
    value.len() == 48
        && value.starts_with(prefix)
        && value[5..]
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'-')
}
pub async fn enroll(cfg: &mut AgentConfig) -> Result<(), Box<dyn std::error::Error>> {
    let bootstrap = cfg
        .enrollment_token
        .as_deref()
        .ok_or("OD_ENROLLMENT_TOKEN not set")?;
    if !token(bootstrap, "odae_") {
        return Err("Invalid one-time enrollment token".into());
    }
    let response = client(cfg)?
        .post(format!(
            "{}/api/device-agent/register",
            cfg.server_url.trim_end_matches('/')
        ))
        .json(&serde_json::json!({"token": bootstrap, "report": report()}))
        .send()
        .await?;
    if response.status() != reqwest::StatusCode::CREATED {
        return Err(format!("Enrollment rejected: HTTP {}", response.status()).into());
    }
    let result: EnrollResponse = response.json().await?;
    if result.schema_version != 1
        || result.agent_protocol != 1
        || !device_id(&result.device_id)
        || !token(&result.device_token, "odad_")
        || chrono::DateTime::parse_from_rfc3339(&result.credential_expires_at)?.timestamp()
            <= chrono::Utc::now().timestamp()
    {
        return Err("Unconfirmed agent enrollment response".into());
    }
    cfg.device_id = Some(result.device_id.clone());
    cfg.device_token = Some(result.device_token);
    cfg.enrollment_token = None;
    cfg.save()?;
    info!("Agent enrolled. Device ID: {}", result.device_id);
    Ok(())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HeartbeatResponse {
    schema_version: u8,
    agent_protocol: u8,
    device_id: String,
    received_at: String,
    compliance: ComplianceResult,
    sync: Option<SyncCompletion>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncCompletion {
    id: String,
    status: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ComplianceResult {
    status: String,
    policy_revision: String,
    evaluated_at: String,
}
async fn transmit(cfg: &AgentConfig) -> Result<ComplianceResult, Box<dyn std::error::Error>> {
    let id = cfg.device_id.as_deref().ok_or("Device not enrolled")?;
    let credential = cfg.device_token.as_deref().ok_or("Device not enrolled")?;
    if !device_id(id) || !token(credential, "odad_") {
        return Err("Invalid saved device credential".into());
    }
    let command = crate::commands::claim(cfg, id, credential).await?;
    let inventory = tokio::task::spawn_blocking(crate::inventory::collect).await?;
    let security = crate::compliance::collect().await;
    let mut body = serde_json::json!({"deviceId": id, "report": report(), "inventory": inventory, "security": security});
    if let Some(command) = &command {
        body["sync"] = serde_json::json!({"id":command.id,"leaseToken":command.lease_token});
    }
    let response = client(cfg)?
        .post(format!(
            "{}/api/device-agent/heartbeat",
            cfg.server_url.trim_end_matches('/')
        ))
        .bearer_auth(credential)
        .json(&body)
        .send()
        .await?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!("Heartbeat rejected: HTTP {}", response.status()).into());
    }
    let result: HeartbeatResponse = response.json().await?;
    if result.schema_version != 1
        || result.agent_protocol != 1
        || result.device_id != id
        || chrono::DateTime::parse_from_rfc3339(&result.received_at)?.timestamp() <= 0
    {
        return Err("Unconfirmed heartbeat response".into());
    }
    if !["compliant", "non-compliant", "unknown", "not-configured"]
        .contains(&result.compliance.status.as_str())
        || result
            .compliance
            .policy_revision
            .parse::<u64>()
            .ok()
            .filter(|value| {
                value.to_string() == result.compliance.policy_revision && *value <= i64::MAX as u64
            })
            .is_none()
        || chrono::DateTime::parse_from_rfc3339(&result.compliance.evaluated_at)?.timestamp() <= 0
    {
        return Err("Unconfirmed compliance assessment".into());
    }
    if !match (&command, &result.sync) {
        (None, None) => true,
        (Some(command), Some(receipt)) => receipt.id == command.id && receipt.status == "completed",
        _ => false,
    } {
        return Err("Actual sync receipt unconfirmed".into());
    }
    Ok(result.compliance)
}
pub async fn heartbeat(cfg: &AgentConfig) -> Result<(), Box<dyn std::error::Error>> {
    transmit(cfg).await.map(|_| ())
}
pub async fn check_compliance(cfg: &AgentConfig) -> Result<(), Box<dyn std::error::Error>> {
    let assessment = transmit(cfg).await?;
    if assessment.status == "compliant" {
        info!(
            "Server compliance assessment: compliant, policy revision {}",
            assessment.policy_revision
        );
        Ok(())
    } else {
        Err(format!(
            "Server compliance assessment: {} (policy revision {})",
            assessment.status, assessment.policy_revision
        )
        .into())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_unsafe_origins() {
        for origin in [
            "http://company.example",
            "https://a.example/path",
            "https://u:p@a.example",
            "https://a.example?token=secret",
        ] {
            let cfg = AgentConfig {
                server_url: origin.into(),
                ..Default::default()
            };
            assert!(client(&cfg).is_err());
        }
    }
    #[test]
    fn validates_device_only_credentials() {
        assert!(token(&format!("odad_{}", "a".repeat(43)), "odad_"));
        assert!(!token("human.jwt", "odad_"));
        assert!(!token(&format!("odae_{}", "a".repeat(43)), "odad_"));
    }
}
