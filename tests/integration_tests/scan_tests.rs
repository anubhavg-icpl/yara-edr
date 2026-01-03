//! Integration tests for file scanning.

#![allow(clippy::unwrap_used)]

use std::fs;
use tempfile::TempDir;
use yara_edr::config::RulesConfig;
use yara_edr::engine::Scanner;

/// EICAR test string - standard antivirus test file content.
const EICAR_CONTENT: &str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Test YARA rule for detecting EICAR.
const EICAR_RULE: &str = r#"
rule EICAR_Test_File {
    meta:
        description = "Detects EICAR test file"
        severity = "high"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
"#;

#[test]
fn test_scan_eicar_file() {
    let temp_dir = TempDir::new().unwrap();

    // Create YARA rule file
    let rules_dir = temp_dir.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(rules_dir.join("test.yar"), EICAR_RULE).unwrap();

    // Create test file with EICAR content
    let test_file = temp_dir.path().join("eicar.txt");
    fs::write(&test_file, EICAR_CONTENT).unwrap();

    // Configure scanner
    let config = RulesConfig {
        paths: vec![rules_dir],
        auto_reload: false,
        reload_interval: 0,
        scan_timeout: 60,
    };

    // Create scanner and load rules
    let scanner = Scanner::new(config);
    scanner.load_rules().unwrap();

    // Scan the file
    let result = scanner.scan_file(&test_file).unwrap();

    // Verify detection
    assert!(result.is_match);
    assert!(!result.matches.is_empty());
    assert!(result.matches.iter().any(|m| m.rule == "EICAR_Test_File"));
}

#[test]
fn test_scan_clean_file() {
    let temp_dir = TempDir::new().unwrap();

    // Create YARA rule file
    let rules_dir = temp_dir.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(rules_dir.join("test.yar"), EICAR_RULE).unwrap();

    // Create clean test file
    let test_file = temp_dir.path().join("clean.txt");
    fs::write(&test_file, "This is a clean file with no malware").unwrap();

    // Configure scanner
    let config = RulesConfig {
        paths: vec![rules_dir],
        auto_reload: false,
        reload_interval: 0,
        scan_timeout: 60,
    };

    // Create scanner and load rules
    let scanner = Scanner::new(config);
    scanner.load_rules().unwrap();

    // Scan the file
    let result = scanner.scan_file(&test_file).unwrap();

    // Verify no detection
    assert!(!result.is_match);
    assert!(result.matches.is_empty());
}

#[test]
fn test_scan_buffer() {
    let temp_dir = TempDir::new().unwrap();

    // Create YARA rule file
    let rules_dir = temp_dir.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(rules_dir.join("test.yar"), EICAR_RULE).unwrap();

    // Configure scanner
    let config = RulesConfig {
        paths: vec![rules_dir],
        auto_reload: false,
        reload_interval: 0,
        scan_timeout: 60,
    };

    // Create scanner and load rules
    let scanner = Scanner::new(config);
    scanner.load_rules().unwrap();

    // Scan EICAR content as buffer
    let result = scanner
        .scan_buffer(EICAR_CONTENT.as_bytes(), "memory")
        .unwrap();

    // Verify detection
    assert!(result.is_match);
    assert!(result.matches.iter().any(|m| m.rule == "EICAR_Test_File"));
}
