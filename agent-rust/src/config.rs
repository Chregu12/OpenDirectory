use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub server_url: String,
    pub enrollment_token: Option<String>,
    pub device_id: Option<String>,
    pub device_token: Option<String>,
    pub insecure_skip_verify: bool,
    pub heartbeat_interval_secs: u64,
    pub command_poll_interval_secs: u64,
    pub compliance_interval_secs: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: std::env::var("OD_SERVER_URL").unwrap_or_default(),
            enrollment_token: std::env::var("OD_ENROLLMENT_TOKEN").ok(),
            device_id: std::env::var("OD_DEVICE_ID").ok(),
            device_token: std::env::var("OD_DEVICE_TOKEN").ok(),
            insecure_skip_verify: std::env::var("OD_INSECURE").map(|v| v == "true").unwrap_or(false),
            heartbeat_interval_secs: 60,
            command_poll_interval_secs: 30,
            compliance_interval_secs: 300,
        }
    }
}

impl AgentConfig {
    pub fn config_path() -> PathBuf {
        if cfg!(target_os = "windows") {
            PathBuf::from(std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:\\ProgramData".into()))
                .join("OpenDirectory").join("agent.json")
        } else if cfg!(target_os = "macos") {
            PathBuf::from("/Library/Application Support/OpenDirectory/agent.json")
        } else {
            PathBuf::from("/etc/opendirectory/agent.json")
        }
    }

    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let path = Self::config_path();
        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            let mut cfg: Self = serde_json::from_str(&data)?;
            // Override from env
            if let Ok(v) = std::env::var("OD_SERVER_URL") { cfg.server_url = v; }
            if let Ok(v) = std::env::var("OD_DEVICE_TOKEN") { cfg.device_token = Some(v); }
            if let Ok(v) = std::env::var("OD_DEVICE_ID") { cfg.device_id = Some(v); }
            Ok(cfg)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, data)?;
        Ok(())
    }
}
