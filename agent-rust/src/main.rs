use clap::{Parser, Subcommand};
use log::{error, info, warn};
use std::time::Duration;
use tokio::time::sleep;

mod config;
mod enrollment;
mod commands;
mod compliance;

use config::AgentConfig;

#[derive(Parser)]
#[command(name = "od-agent-service", version = "1.0.0", about = "OpenDirectory MDM Agent")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(long, env = "OD_SERVER_URL")]
    server_url: Option<String>,

    #[arg(long, env = "OD_ENROLLMENT_TOKEN")]
    enrollment_token: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Enroll this device with OpenDirectory
    Enroll,
    /// Run the agent daemon
    Run,
    /// Check device compliance and report
    Compliance,
    /// Show current configuration
    Status,
    /// Install as system service
    Install,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    let cli = Cli::parse();

    let mut cfg = AgentConfig::load().unwrap_or_default();

    if let Some(url) = cli.server_url {
        cfg.server_url = url;
    }
    if let Some(token) = cli.enrollment_token {
        cfg.enrollment_token = Some(token);
    }

    let result = match cli.command.unwrap_or(Commands::Run) {
        Commands::Enroll => enrollment::enroll(&mut cfg).await,
        Commands::Run => run_daemon(cfg).await,
        Commands::Compliance => compliance::check_and_report(&cfg).await,
        Commands::Status => {
            println!("Server URL: {}", cfg.server_url);
            println!("Device ID:  {}", cfg.device_id.as_deref().unwrap_or("(not enrolled)"));
            println!("Enrolled:   {}", cfg.device_token.is_some());
            Ok(())
        }
        Commands::Install => install_service(),
    };

    if let Err(e) = result {
        error!("Fatal error: {}", e);
        std::process::exit(1);
    }
}

async fn run_daemon(cfg: AgentConfig) -> Result<(), Box<dyn std::error::Error>> {
    if cfg.device_token.is_none() {
        return Err("Device not enrolled. Run: od-agent-service enroll".into());
    }

    info!("OpenDirectory Agent starting. Device: {}",
        cfg.device_id.as_deref().unwrap_or("unknown"));

    let cfg = std::sync::Arc::new(cfg);

    // Start concurrent tasks
    let hb_cfg = cfg.clone();
    let cmd_cfg = cfg.clone();
    let comp_cfg = cfg.clone();

    let heartbeat_task = tokio::spawn(async move {
        loop {
            if let Err(e) = send_heartbeat(&hb_cfg).await {
                warn!("Heartbeat failed: {}", e);
            }
            sleep(Duration::from_secs(60)).await;
        }
    });

    let commands_task = tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(30)).await;
            if let Err(e) = commands::poll_and_execute(&cmd_cfg).await {
                warn!("Command poll failed: {}", e);
            }
        }
    });

    let compliance_task = tokio::spawn(async move {
        loop {
            if let Err(e) = compliance::check_and_report(&comp_cfg).await {
                warn!("Compliance check failed: {}", e);
            }
            sleep(Duration::from_secs(300)).await;
        }
    });

    tokio::select! {
        _ = heartbeat_task => {},
        _ = commands_task => {},
        _ = compliance_task => {},
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl-C, shutting down.");
        }
    }

    Ok(())
}

async fn send_heartbeat(cfg: &AgentConfig) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(cfg.insecure_skip_verify)
        .timeout(Duration::from_secs(15))
        .build()?;

    let payload = serde_json::json!({
        "deviceId": cfg.device_id,
        "platform": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "agentVersion": "1.0.0",
    });

    let url = format!("{}/api/enrollment/heartbeat", cfg.server_url);
    client.post(&url)
        .bearer_auth(cfg.device_token.as_deref().unwrap_or(""))
        .json(&payload)
        .send()
        .await?;

    Ok(())
}

fn install_service() -> Result<(), Box<dyn std::error::Error>> {
    let exe_path = std::env::current_exe()?;

    #[cfg(target_os = "linux")]
    {
        let service_content = format!(
            "[Unit]\nDescription=OpenDirectory MDM Agent\nAfter=network.target\n\n[Service]\nExecStart={} run\nRestart=always\nRestartSec=10\nEnvironment=RUST_LOG=info\n\n[Install]\nWantedBy=multi-user.target\n",
            exe_path.display()
        );
        std::fs::write("/etc/systemd/system/od-agent.service", service_content)?;
        println!("Installed systemd service. Run: systemctl enable --now od-agent");
    }

    #[cfg(target_os = "macos")]
    {
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>com.opendirectory.agent</string>\n<key>ProgramArguments</key><array><string>{}</string><string>run</string></array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n</dict></plist>\n",
            exe_path.display()
        );
        let plist_path = "/Library/LaunchDaemons/com.opendirectory.agent.plist";
        std::fs::write(plist_path, plist)?;
        println!("Installed LaunchDaemon. Run: launchctl load {}", plist_path);
    }

    Ok(())
}
