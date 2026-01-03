//! Common test utilities and fixtures for yara-edr tests.

#![allow(dead_code)]
#![allow(clippy::expect_used)]

use std::path::PathBuf;
use tempfile::TempDir;

/// Creates a temporary directory for test files.
pub fn create_temp_dir() -> TempDir {
    TempDir::new().expect("Failed to create temp directory")
}

/// Creates a test file with the given content.
pub fn create_test_file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("Failed to write test file");
    path
}

/// Test YARA rule for detecting EICAR test file.
pub const EICAR_RULE: &str = r#"
rule EICAR_Test_File {
    meta:
        description = "Detects EICAR test file"
        severity = "info"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
"#;

/// EICAR test string content.
pub const EICAR_CONTENT: &str =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
