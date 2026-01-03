//! Unit tests for YARA rule management.

use std::path::PathBuf;
use yara_edr::engine::RuleStats;

#[test]
fn test_rule_stats_display() {
    let stats = RuleStats {
        file_count: 5,
        rules_loaded: true,
        auto_reload: true,
        paths: vec![PathBuf::from("/etc/yara-edr/rules")],
    };

    let display = format!("{stats}");
    assert!(display.contains("Files loaded: 5"));
    assert!(display.contains("Rules loaded: true"));
}

#[test]
fn test_rule_stats_default() {
    let stats = RuleStats {
        file_count: 0,
        rules_loaded: false,
        auto_reload: false,
        paths: vec![],
    };

    let display = format!("{stats}");
    assert!(display.contains("Files loaded: 0"));
    assert!(display.contains("Rules loaded: false"));
}
