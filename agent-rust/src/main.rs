use clap::{Parser, Subcommand};
use log::{error, info, warn};
use std::time::Duration;

mod config;
mod enrollment;

use config::AgentConfig;

#[derive(Parser)]
#[command(
    name = "od-agent-service",
    version = "1.1.0",
    about = "OpenDirectory MDM Agent"
)]
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
    /// Send one authenticated heartbeat
    Heartbeat,
    /// Show current configuration
    Status,
    /// Install as system service
    Install,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    let mut cfg = match AgentConfig::load() {
        Ok(cfg) => cfg,
        Err(_) => {
            error!("Cannot read agent configuration");
            std::process::exit(1);
        }
    };

    if let Some(url) = cli.server_url {
        cfg.server_url = url;
    }
    if let Some(token) = cli.enrollment_token {
        cfg.enrollment_token = Some(token);
    }

    let result = match cli.command.unwrap_or(Commands::Run) {
        Commands::Enroll => enrollment::enroll(&mut cfg).await,
        Commands::Run => run_daemon(cfg).await,
        Commands::Compliance => {
            Err("Compliance policies are not configured for agent protocol 1".into())
        }
        Commands::Heartbeat => enrollment::heartbeat(&cfg).await,
        Commands::Status => {
            println!("Server URL: {}", cfg.server_url);
            println!(
                "Device ID:  {}",
                cfg.device_id.as_deref().unwrap_or("(not enrolled)")
            );
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

    info!(
        "OpenDirectory Agent starting. Device: {}",
        cfg.device_id.as_deref().unwrap_or("unknown")
    );

    let mut ticker = tokio::time::interval(Duration::from_secs(
        cfg.heartbeat_interval_secs.clamp(30, 300),
    ));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(error) = enrollment::heartbeat(&cfg).await { warn!("Heartbeat failed: {}", error); }
            }
            _ = tokio::signal::ctrl_c() => { info!("Agent stopped."); break; }
        }
    }

    Ok(())
}

fn install_service() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    return Err("Use an elevated scheduled task to run od-agent-service run at startup; Windows service installation is not supported".into());
    #[cfg(not(windows))]
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
