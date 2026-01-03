//! YARA-EDR: A YARA-powered Endpoint Detection and Response agent for Linux
//!
//! This library provides the core functionality for the YARA-EDR agent,
//! including file monitoring, process scanning, and threat detection.

pub mod alerts;
pub mod config;
pub mod daemon;
pub mod detection;
pub mod engine;
pub mod monitors;
pub mod response;
pub mod utils;

// Re-export commonly used items at crate level
pub use config::Config;

use thiserror::Error;

/// Main error type for YARA-EDR
#[derive(Error, Debug)]
pub enum EdrError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("YARA engine error: {0}")]
    Yara(String),

    #[error("File monitoring error: {0}")]
    FileMonitor(String),

    #[error("Process monitoring error: {0}")]
    ProcessMonitor(String),

    #[error("Scanning error: {0}")]
    Scan(String),

    #[error("Response action error: {0}")]
    Response(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Daemon error: {0}")]
    Daemon(String),
}

pub type Result<T> = std::result::Result<T, EdrError>;

/// EDR Agent version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default configuration file path
pub const DEFAULT_CONFIG_PATH: &str = "/etc/yara-edr/config.toml";

/// Default rules directory
pub const DEFAULT_RULES_PATH: &str = "/etc/yara-edr/rules";

/// Default log directory
pub const DEFAULT_LOG_DIR: &str = "/var/log/yara-edr";

/// Default quarantine directory
pub const DEFAULT_QUARANTINE_DIR: &str = "/var/lib/yara-edr/quarantine";

/// Default PID file path
pub const DEFAULT_PID_FILE: &str = "/var/run/yara-edr.pid";
