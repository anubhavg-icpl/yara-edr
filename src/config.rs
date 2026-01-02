//! Configuration management for YARA-EDR
//!
//! Handles loading, parsing, and validating configuration from TOML files.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::{EdrError, Result};

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,

    #[serde(default)]
    pub rules: RulesConfig,

    #[serde(default)]
    pub file_monitor: FileMonitorConfig,

    #[serde(default)]
    pub process_monitor: ProcessMonitorConfig,

    #[serde(default)]
    pub response: ResponseConfig,

    #[serde(default)]
    pub alerts: AlertsConfig,
}

/// General configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Path to the log file
    #[serde(default = "default_log_file")]
    pub log_file: PathBuf,

    /// Path to the PID file for daemon mode
    #[serde(default = "default_pid_file")]
    pub pid_file: PathBuf,

    /// Number of worker threads
    #[serde(default = "default_workers")]
    pub workers: usize,
}

/// YARA rules configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    /// Paths to search for YARA rules
    #[serde(default = "default_rules_paths")]
    pub paths: Vec<PathBuf>,

    /// Enable automatic rule reloading
    #[serde(default = "default_true")]
    pub auto_reload: bool,

    /// Interval in seconds between rule reload checks
    #[serde(default = "default_reload_interval")]
    pub reload_interval: u64,

    /// Scan timeout in seconds
    #[serde(default = "default_scan_timeout")]
    pub scan_timeout: u64,
}

/// File monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMonitorConfig {
    /// Enable file monitoring
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Paths to watch for file changes
    #[serde(default = "default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,

    /// Enable recursive watching
    #[serde(default = "default_true")]
    pub recursive: bool,

    /// File extensions to scan (empty = all files)
    #[serde(default = "default_extensions")]
    pub extensions: Vec<String>,

    /// Patterns to exclude from scanning
    #[serde(default = "default_exclude_patterns")]
    pub exclude_patterns: Vec<String>,

    /// Maximum file size to scan in bytes (0 = unlimited)
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,

    /// Debounce time in milliseconds for file events
    #[serde(default = "default_debounce_ms")]
    pub debounce_ms: u64,
}

/// Process monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMonitorConfig {
    /// Enable process monitoring
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Scan processes on execution
    #[serde(default = "default_true")]
    pub scan_on_exec: bool,

    /// Interval in seconds for periodic process scanning
    #[serde(default = "default_scan_interval")]
    pub scan_interval: u64,

    /// Enable memory scanning
    #[serde(default = "default_true")]
    pub memory_scan: bool,

    /// Scan command line arguments
    #[serde(default = "default_true")]
    pub scan_cmdline: bool,

    /// PIDs to exclude from scanning
    #[serde(default)]
    pub exclude_pids: Vec<i32>,

    /// Process names to exclude from scanning
    #[serde(default)]
    pub exclude_names: Vec<String>,
}

/// Response actions configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    /// Path to quarantine directory
    #[serde(default = "default_quarantine_path")]
    pub quarantine_path: PathBuf,

    /// Automatically quarantine detected files
    #[serde(default)]
    pub auto_quarantine: bool,

    /// Automatically kill detected processes
    #[serde(default)]
    pub auto_kill: bool,

    /// Preserve file metadata in quarantine
    #[serde(default = "default_true")]
    pub preserve_metadata: bool,

    /// Maximum quarantine size in bytes (0 = unlimited)
    #[serde(default)]
    pub max_quarantine_size: u64,
}

/// Alerting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertsConfig {
    /// Alert output type: file, stdout, syslog
    #[serde(default = "default_alert_output")]
    pub output: String,

    /// Path to alerts file (when output = file)
    #[serde(default = "default_alerts_file")]
    pub file_path: PathBuf,

    /// Include matched data in alerts
    #[serde(default = "default_true")]
    pub include_match_data: bool,

    /// Maximum match data length to include
    #[serde(default = "default_max_match_data")]
    pub max_match_data: usize,

    /// Alert severity threshold (info, low, medium, high, critical)
    #[serde(default = "default_severity_threshold")]
    pub severity_threshold: String,
}

// Default value functions
fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_file() -> PathBuf {
    PathBuf::from("/var/log/yara-edr/edr.log")
}

fn default_pid_file() -> PathBuf {
    PathBuf::from("/var/run/yara-edr.pid")
}

fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
        .max(2)
}

fn default_rules_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/etc/yara-edr/rules"),
        PathBuf::from("./rules"),
    ]
}

fn default_true() -> bool {
    true
}

fn default_reload_interval() -> u64 {
    300 // 5 minutes
}

fn default_scan_timeout() -> u64 {
    60 // 60 seconds
}

fn default_watch_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/home"),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
        PathBuf::from("/opt"),
    ]
}

fn default_extensions() -> Vec<String> {
    vec![
        "exe".to_string(),
        "dll".to_string(),
        "so".to_string(),
        "sh".to_string(),
        "py".to_string(),
        "pl".to_string(),
        "rb".to_string(),
        "bin".to_string(),
        "elf".to_string(),
    ]
}

fn default_exclude_patterns() -> Vec<String> {
    vec![
        "/proc/*".to_string(),
        "/sys/*".to_string(),
        "/dev/*".to_string(),
        "*.log".to_string(),
        "*.tmp".to_string(),
    ]
}

fn default_max_file_size() -> u64 {
    100 * 1024 * 1024 // 100 MB
}

fn default_debounce_ms() -> u64 {
    500
}

fn default_scan_interval() -> u64 {
    3600 // 1 hour
}

fn default_quarantine_path() -> PathBuf {
    PathBuf::from("/var/lib/yara-edr/quarantine")
}

fn default_alert_output() -> String {
    "file".to_string()
}

fn default_alerts_file() -> PathBuf {
    PathBuf::from("/var/log/yara-edr/alerts.json")
}

fn default_max_match_data() -> usize {
    256
}

fn default_severity_threshold() -> String {
    "info".to_string()
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            log_file: default_log_file(),
            pid_file: default_pid_file(),
            workers: default_workers(),
        }
    }
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            paths: default_rules_paths(),
            auto_reload: true,
            reload_interval: default_reload_interval(),
            scan_timeout: default_scan_timeout(),
        }
    }
}

impl Default for FileMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            watch_paths: default_watch_paths(),
            recursive: true,
            extensions: default_extensions(),
            exclude_patterns: default_exclude_patterns(),
            max_file_size: default_max_file_size(),
            debounce_ms: default_debounce_ms(),
        }
    }
}

impl Default for ProcessMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_on_exec: true,
            scan_interval: default_scan_interval(),
            memory_scan: true,
            scan_cmdline: true,
            exclude_pids: vec![],
            exclude_names: vec![],
        }
    }
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            quarantine_path: default_quarantine_path(),
            auto_quarantine: false,
            auto_kill: false,
            preserve_metadata: true,
            max_quarantine_size: 0,
        }
    }
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            output: default_alert_output(),
            file_path: default_alerts_file(),
            include_match_data: true,
            max_match_data: default_max_match_data(),
            severity_threshold: default_severity_threshold(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            rules: RulesConfig::default(),
            file_monitor: FileMonitorConfig::default(),
            process_monitor: ProcessMonitorConfig::default(),
            response: ResponseConfig::default(),
            alerts: AlertsConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        if !path.exists() {
            warn!("Config file not found at {:?}, using defaults", path);
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)
            .map_err(|e| EdrError::Config(format!("Failed to read config file: {}", e)))?;

        let config: Config = toml::from_str(&content)
            .map_err(|e| EdrError::Config(format!("Failed to parse config file: {}", e)))?;

        config.validate()?;

        info!("Loaded configuration from {:?}", path);
        Ok(config)
    }

    /// Load configuration from a string
    pub fn from_str(content: &str) -> Result<Self> {
        let config: Config = toml::from_str(content)
            .map_err(|e| EdrError::Config(format!("Failed to parse config: {}", e)))?;

        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate log level
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.general.log_level.to_lowercase().as_str()) {
            return Err(EdrError::Config(format!(
                "Invalid log level: {}",
                self.general.log_level
            )));
        }

        // Validate alert output
        let valid_outputs = ["file", "stdout", "syslog"];
        if !valid_outputs.contains(&self.alerts.output.to_lowercase().as_str()) {
            return Err(EdrError::Config(format!(
                "Invalid alert output: {}",
                self.alerts.output
            )));
        }

        // Validate severity threshold
        let valid_severities = ["info", "low", "medium", "high", "critical"];
        if !valid_severities.contains(&self.alerts.severity_threshold.to_lowercase().as_str()) {
            return Err(EdrError::Config(format!(
                "Invalid severity threshold: {}",
                self.alerts.severity_threshold
            )));
        }

        Ok(())
    }

    /// Save configuration to a TOML file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| EdrError::Config(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(path, content)?;
        Ok(())
    }

    /// Create necessary directories for the configuration
    pub fn create_directories(&self) -> Result<()> {
        // Create log directory
        if let Some(parent) = self.general.log_file.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Create alerts directory
        if let Some(parent) = self.alerts.file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Create quarantine directory
        std::fs::create_dir_all(&self.response.quarantine_path)?;

        // Create PID file directory
        if let Some(parent) = self.general.pid_file.parent() {
            std::fs::create_dir_all(parent)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_from_str() {
        let toml = r#"
            [general]
            log_level = "debug"

            [file_monitor]
            enabled = true
            watch_paths = ["/tmp"]
        "#;

        let config = Config::from_str(toml).unwrap();
        assert_eq!(config.general.log_level, "debug");
        assert!(config.file_monitor.enabled);
    }

    #[test]
    fn test_invalid_log_level() {
        let toml = r#"
            [general]
            log_level = "invalid"
        "#;

        let result = Config::from_str(toml);
        assert!(result.is_err());
    }
}
