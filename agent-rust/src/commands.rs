use crate::config::AgentConfig;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Command {
    pub id: String,
    #[serde(rename = "type")]
    kind: String,
    pub lease_token: String,
    expires_at: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Claim {
    schema_version: u8,
    sync_protocol: u8,
    device_id: String,
    command: Option<Command>,
}
fn valid(command: &Command) -> bool {
    uuid::Uuid::parse_str(&command.id)
        .ok()
        .map(|id| id.to_string() == command.id)
        .unwrap_or(false)
        && command.kind == "inventory.refresh"
        && command
            .lease_token
            .strip_prefix("odsl_")
            .map(|part| {
                part.len() == 43
                    && part.bytes().all(|value| {
                        value.is_ascii_alphanumeric() || value == b'_' || value == b'-'
                    })
            })
            .unwrap_or(false)
        && chrono::DateTime::parse_from_rfc3339(&command.expires_at)
            .map(|time| {
                time.timestamp_millis() > chrono::Utc::now().timestamp_millis()
                    && time.timestamp_millis() <= chrono::Utc::now().timestamp_millis() + 45_000
            })
            .unwrap_or(false)
}
pub async fn claim(
    cfg: &AgentConfig,
    device_id: &str,
    credential: &str,
) -> Result<Option<Command>, Box<dyn std::error::Error>> {
    let response = crate::enrollment::client(cfg)?
        .post(format!(
            "{}/api/device-agent/sync/claim",
            cfg.server_url.trim_end_matches('/')
        ))
        .bearer_auth(credential)
        .json(&serde_json::json!({"deviceId":device_id}))
        .send()
        .await?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!("Sync polling rejected: HTTP {}", response.status()).into());
    }
    let result: Claim = response.json().await?;
    if result.schema_version != 1
        || result.sync_protocol != 1
        || result.device_id != device_id
        || result
            .command
            .as_ref()
            .is_some_and(|command| !valid(command))
    {
        return Err("Unconfirmed device sync offer".into());
    }
    Ok(result.command)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn command() -> Command {
        Command {
            id: uuid::Uuid::new_v4().to_string(),
            kind: "inventory.refresh".into(),
            lease_token: format!("odsl_{}", "a".repeat(43)),
            expires_at: (chrono::Utc::now() + chrono::Duration::seconds(30)).to_rfc3339(),
        }
    }
    #[test]
    fn only_bounded_read_only_sync_can_be_offered() {
        assert!(valid(&command()));
        let mut other = command();
        other.kind = "restart".into();
        assert!(!valid(&other));
        let mut other = command();
        other.lease_token = "arbitrary".into();
        assert!(!valid(&other));
        let mut other = command();
        other.expires_at = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        assert!(!valid(&other));
        let mut other = command();
        other.expires_at = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        assert!(!valid(&other));
    }
}
