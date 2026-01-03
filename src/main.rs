//! YARA-EDR: Linux Endpoint Detection and Response Agent
//!
//! A comprehensive YARA-powered EDR agent for Linux.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{Level, error, info};
use tracing_subscriber::FmtSubscriber;

use yara_edr::config::Config;
use yara_edr::daemon::{self, Daemon};
use yara_edr::detection::{FileScanner, MemoryScanner};
use yara_edr::engine::RuleManager;
use yara_edr::response::QuarantineManager;
use yara_edr::{DEFAULT_CONFIG_PATH, Result};

/// YARA-EDR: Linux Endpoint Detection and Response Agent
#[derive(Parser)]
#[command(name = "yara-edr")]
#[command(author = "Anubhav")]
#[command(version)]
#[command(about = "YARA-powered EDR agent for Linux", long_about = None)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Quiet mode (only errors)
    #[arg(short, long)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan files or directories
    Scan {
        /// Path(s) to scan
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Recursive scan
        #[arg(short, long)]
        recursive: bool,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Scan a running process
    ScanProcess {
        /// Process ID to scan
        #[arg(required = true)]
        pid: i32,
    },

    /// Scan all running processes
    ScanAllProcesses,

    /// Start the EDR daemon
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
    },

    /// Stop the running daemon
    Stop,

    /// Show daemon status
    Status,

    /// Reload YARA rules
    Reload,

    /// Quarantine management
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },

    /// Generate default configuration file
    InitConfig {
        /// Output path for configuration file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Validate configuration and rules
    Validate,
}

#[derive(Subcommand)]
enum QuarantineAction {
    /// List quarantined files
    List,
    /// Restore a quarantined file
    Restore {
        /// Quarantine entry ID
        id: String,
    },
    /// Delete a quarantined file permanently
    Delete {
        /// Quarantine entry ID
        id: String,
    },
    /// Show quarantine statistics
    Stats,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.quiet {
        Level::ERROR
    } else if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .finish();

    if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
        eprintln!("Failed to set tracing subscriber: {e}");
        std::process::exit(1);
    }

    // Run command
    if let Err(e) = run_command(cli).await {
        error!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run_command(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Scan {
            paths,
            recursive,
            format,
        } => cmd_scan(&cli.config, paths, recursive, &format).await,

        Commands::ScanProcess { pid } => cmd_scan_process(&cli.config, pid).await,

        Commands::ScanAllProcesses => cmd_scan_all_processes(&cli.config).await,

        Commands::Start { foreground } => cmd_start(&cli.config, foreground).await,

        Commands::Stop => cmd_stop(&cli.config),

        Commands::Status => cmd_status(&cli.config),

        Commands::Reload => cmd_reload(&cli.config),

        Commands::Quarantine { action } => cmd_quarantine(&cli.config, action),

        Commands::InitConfig { output } => cmd_init_config(output),

        Commands::Validate => cmd_validate(&cli.config),
    }
}

/// Scan files or directories
async fn cmd_scan(
    config_path: &PathBuf,
    paths: Vec<PathBuf>,
    recursive: bool,
    format: &str,
) -> Result<()> {
    info!("Loading configuration...");
    let mut config = Config::load(config_path)?;
    config.file_monitor.recursive = recursive;

    info!("Initializing YARA rules...");
    let mut rule_manager = RuleManager::new(config.rules.clone());
    rule_manager.initialize()?;

    let scanner = rule_manager.scanner();
    let file_scanner = FileScanner::new(scanner, config.file_monitor.clone());

    let mut total_files = 0;
    let mut total_detections = 0;

    for path in paths {
        if !path.exists() {
            error!("Path not found: {:?}", path);
            continue;
        }

        println!("Scanning: {path:?}");

        if path.is_file() {
            match file_scanner.scan_file(&path) {
                Ok(result) => {
                    total_files += 1;
                    if result.is_match {
                        total_detections += 1;
                        print_scan_result(&result, format);
                    }
                },
                Err(e) => {
                    error!("Failed to scan {:?}: {}", path, e);
                },
            }
        } else if path.is_dir() {
            match file_scanner.scan_directory(&path) {
                Ok(results) => {
                    for result in results {
                        total_files += 1;
                        if result.is_match {
                            total_detections += 1;
                            print_scan_result(&result, format);
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to scan directory {:?}: {}", path, e);
                },
            }
        }
    }

    println!("\n=== Scan Complete ===");
    println!("Files scanned: {total_files}");
    println!("Detections: {total_detections}");

    Ok(())
}

/// Print scan result
fn print_scan_result(result: &yara_edr::engine::ScanResult, format: &str) {
    if format == "json" {
        if let Ok(json) = serde_json::to_string_pretty(result) {
            println!("{json}");
        }
    } else {
        println!("\n[DETECTION] {}", result.target);
        for m in &result.matches {
            println!("  Rule: {} ({})", m.rule, m.namespace);
            if !m.tags.is_empty() {
                println!("    Tags: {}", m.tags.join(", "));
            }
            for (key, value) in &m.metadata {
                println!("    {key}: {value}");
            }
            if !m.strings.is_empty() {
                println!("    Strings matched: {}", m.strings.len());
                for s in m.strings.iter().take(5) {
                    println!("      {} @ 0x{:x}", s.identifier, s.offset);
                }
            }
        }
        if let Some(hashes) = &result.hashes {
            println!("  MD5: {}", hashes.md5);
            println!("  SHA256: {}", hashes.sha256);
        }
    }
}

/// Scan a process
async fn cmd_scan_process(config_path: &PathBuf, pid: i32) -> Result<()> {
    info!("Loading configuration...");
    let config = Config::load(config_path)?;

    info!("Initializing YARA rules...");
    let mut rule_manager = RuleManager::new(config.rules.clone());
    rule_manager.initialize()?;

    let scanner = rule_manager.scanner();
    let memory_scanner = MemoryScanner::new(scanner, config.process_monitor.clone());

    println!("Scanning process: PID {pid}");

    match memory_scanner.scan_process(pid) {
        Ok(result) => {
            if result.is_match {
                println!("\n[DETECTION] PID {pid}");
                for m in &result.matches {
                    println!("  Rule: {} ({})", m.rule, m.namespace);
                }
            } else {
                println!("No threats detected in process {pid}");
            }
        },
        Err(e) => {
            error!("Failed to scan process {}: {}", pid, e);
        },
    }

    Ok(())
}

/// Scan all processes
async fn cmd_scan_all_processes(config_path: &PathBuf) -> Result<()> {
    info!("Loading configuration...");
    let config = Config::load(config_path)?;

    info!("Initializing YARA rules...");
    let mut rule_manager = RuleManager::new(config.rules.clone());
    rule_manager.initialize()?;

    let scanner = rule_manager.scanner();
    let memory_scanner = MemoryScanner::new(scanner, config.process_monitor.clone());

    println!("Scanning all running processes...");

    let summary = memory_scanner.scan_all_processes().await?;
    println!("{summary}");

    Ok(())
}

/// Start the daemon
async fn cmd_start(config_path: &PathBuf, foreground: bool) -> Result<()> {
    info!("Loading configuration...");
    let config = Config::load(config_path)?;

    // Check if already running
    if daemon::is_daemon_running(&config.general.pid_file) {
        error!("Daemon is already running");
        return Ok(());
    }

    // Create necessary directories
    config.create_directories()?;

    if !foreground {
        info!("Daemonizing...");
        daemon::daemonize()?;
    }

    // Create and start daemon
    let daemon = Daemon::new(config)?;

    // Setup signal handler
    let daemon_clone = std::sync::Arc::new(daemon);
    let daemon_for_signal = daemon_clone.clone();

    ctrlc::set_handler(move || {
        info!("Received shutdown signal");
        daemon_for_signal.stop();
    })
    .map_err(|e| yara_edr::EdrError::Daemon(format!("Failed to set signal handler: {e}")))?;

    // Start daemon
    daemon_clone.start().await?;

    Ok(())
}

/// Stop the daemon
fn cmd_stop(config_path: &PathBuf) -> Result<()> {
    let config = Config::load(config_path)?;

    if !daemon::is_daemon_running(&config.general.pid_file) {
        println!("Daemon is not running");
        return Ok(());
    }

    daemon::stop_daemon(&config.general.pid_file)?;
    println!("Stop signal sent to daemon");

    Ok(())
}

/// Show daemon status
fn cmd_status(config_path: &PathBuf) -> Result<()> {
    let config = Config::load(config_path)?;

    if daemon::is_daemon_running(&config.general.pid_file) {
        let pid = std::fs::read_to_string(&config.general.pid_file)?;
        println!("YARA-EDR daemon is running (PID: {})", pid.trim());
    } else {
        println!("YARA-EDR daemon is not running");
    }

    Ok(())
}

/// Reload rules
fn cmd_reload(config_path: &PathBuf) -> Result<()> {
    let config = Config::load(config_path)?;

    if !daemon::is_daemon_running(&config.general.pid_file) {
        println!("Daemon is not running");
        return Ok(());
    }

    // Send SIGHUP to reload
    let pid: i32 = std::fs::read_to_string(&config.general.pid_file)?
        .trim()
        .parse()
        .map_err(|_| yara_edr::EdrError::Daemon("Invalid PID".to_string()))?;

    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGHUP,
    )
    .map_err(|e| yara_edr::EdrError::Daemon(format!("Failed to send SIGHUP: {e}")))?;

    println!("Reload signal sent to daemon");

    Ok(())
}

/// Quarantine management
fn cmd_quarantine(config_path: &PathBuf, action: QuarantineAction) -> Result<()> {
    let config = Config::load(config_path)?;
    let quarantine = QuarantineManager::new(&config.response.quarantine_path)?;

    match action {
        QuarantineAction::List => {
            let entries = quarantine.list();

            if entries.is_empty() {
                println!("No quarantined files");
            } else {
                println!("Quarantined files ({}):", entries.len());
                println!("{:-<80}", "");
                for entry in entries {
                    println!(
                        "ID: {}\n  Original: {:?}\n  Quarantined: {}\n  Size: {} bytes\n  SHA256: {}\n",
                        entry.id,
                        entry.original_path,
                        entry.quarantined_at.format("%Y-%m-%d %H:%M:%S UTC"),
                        entry.size,
                        entry.sha256
                    );
                }
            }
        },

        QuarantineAction::Restore { id } => {
            let uuid = uuid::Uuid::parse_str(&id)
                .map_err(|_| yara_edr::EdrError::Response("Invalid UUID".to_string()))?;

            let mut quarantine = QuarantineManager::new(&config.response.quarantine_path)?;
            let path = quarantine.restore(uuid)?;
            println!("File restored to: {path:?}");
        },

        QuarantineAction::Delete { id } => {
            let uuid = uuid::Uuid::parse_str(&id)
                .map_err(|_| yara_edr::EdrError::Response("Invalid UUID".to_string()))?;

            let mut quarantine = QuarantineManager::new(&config.response.quarantine_path)?;
            quarantine.delete(uuid)?;
            println!("Quarantined file deleted permanently");
        },

        QuarantineAction::Stats => {
            println!("Quarantine Statistics:");
            println!("  Total files: {}", quarantine.count());
            println!("  Total size: {} bytes", quarantine.total_size());
            println!("  Location: {:?}", config.response.quarantine_path);
        },
    }

    Ok(())
}

/// Generate default configuration
fn cmd_init_config(output: Option<PathBuf>) -> Result<()> {
    let config = Config::default();
    let output_path = output.unwrap_or_else(|| PathBuf::from("config.toml"));

    config.save(&output_path)?;
    println!("Configuration file created: {output_path:?}");

    Ok(())
}

/// Validate configuration and rules
fn cmd_validate(config_path: &PathBuf) -> Result<()> {
    println!("Validating configuration...");

    let config = Config::load(config_path)?;
    println!("  Configuration: OK");

    println!("Validating YARA rules...");

    let mut rule_manager = RuleManager::new(config.rules.clone());
    rule_manager.initialize()?;

    let stats = rule_manager.stats();
    println!("  Rules loaded: {} files", stats.file_count);
    println!(
        "  Rules status: {}",
        if stats.rules_loaded { "OK" } else { "FAILED" }
    );

    println!("\nValidation complete!");

    Ok(())
}
