//! Unit tests for configuration module.

#![allow(clippy::unwrap_used)]

use yara_edr::Config;

#[test]
fn test_default_config() {
    let config = Config::default();
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_parse() {
    let toml = r#"
        [general]
        log_level = "debug"

        [file_monitor]
        enabled = true
        watch_paths = ["/tmp"]
    "#;

    let config = Config::parse(toml).unwrap();
    assert_eq!(config.general.log_level, "debug");
    assert!(config.file_monitor.enabled);
}

#[test]
fn test_invalid_log_level() {
    let toml = r#"
        [general]
        log_level = "invalid"
    "#;

    let result = Config::parse(toml);
    assert!(result.is_err());
}

#[test]
fn test_default_values() {
    let config = Config::default();

    // General defaults
    assert_eq!(config.general.log_level, "info");

    // File monitor defaults
    assert!(config.file_monitor.enabled);
    assert!(config.file_monitor.recursive);

    // Process monitor defaults
    assert!(config.process_monitor.enabled);
    assert!(config.process_monitor.memory_scan);

    // Response defaults
    assert!(!config.response.auto_quarantine);
    assert!(!config.response.auto_kill);
}
