use clap::{Parser, Subcommand};
use log::{error, info, warn};
use std::time::Duration;

mod commands;
mod compliance;
mod config;
mod enrollment;
mod installation;
mod inventory;

use config::AgentConfig;

#[derive(Parser)]
#[command(
    name = "od-agent-service",
    version = "1.5.0",
    about = "OpenDirectory MDM Agent"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(long, env = "OD_CONFIG_PATH", global = true)]
    config_path: Option<std::path::PathBuf>,

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
    /// Show local hardware inventory without credentials
    Inventory,
    /// Show local security observations without changing settings
    Security,
    /// Show current configuration
    Status,
    /// Install as system service
    Install {
        /// Show paths without installing or starting anything
        #[arg(long)]
        dry_run: bool,
        /// Back up and replace an existing different OpenDirectory service definition
        #[arg(long)]
        replace_existing: bool,
    },
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    let config_path = cli.config_path.unwrap_or_else(AgentConfig::config_path);
    if matches!(
        cli.command.as_ref(),
        Some(Commands::Install { dry_run: true, .. })
    ) {
        if let Err(error) = installation::preview(config_path) {
            error!("Cannot prepare installation: {}", error);
            std::process::exit(1);
        }
        return;
    }

    let mut cfg = match AgentConfig::load_from(config_path) {
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
        Commands::Compliance => enrollment::check_compliance(&cfg).await,
        Commands::Heartbeat => enrollment::heartbeat(&cfg).await,
        Commands::Inventory => match serde_json::to_string_pretty(&inventory::collect()) {
            Ok(value) => {
                println!("{}", value);
                Ok(())
            }
            Err(error) => Err(error.into()),
        },
        Commands::Security => match serde_json::to_string_pretty(&compliance::collect().await) {
            Ok(value) => {
                println!("{}", value);
                Ok(())
            }
            Err(error) => Err(error.into()),
        },
        Commands::Status => {
            println!("Server URL: {}", cfg.server_url);
            println!(
                "Device ID:  {}",
                cfg.device_id.as_deref().unwrap_or("(not enrolled)")
            );
            println!("Enrolled:   {}", cfg.device_token.is_some());
            Ok(())
        }
        Commands::Install {
            dry_run,
            replace_existing,
        } => installation::install(&cfg, dry_run, replace_existing),
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
