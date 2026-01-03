//! Unit tests for response actions.

use std::path::Path;
use yara_edr::config::ResponseConfig;
use yara_edr::response::ResponseExecutor;

#[test]
fn test_protected_paths() {
    let config = ResponseConfig::default();
    let executor = ResponseExecutor::new(config).unwrap();

    assert!(executor.is_protected_path(Path::new("/bin/bash")));
    assert!(executor.is_protected_path(Path::new("/etc/passwd")));
    assert!(!executor.is_protected_path(Path::new("/tmp/malware")));
    assert!(!executor.is_protected_path(Path::new("/home/user/file")));
}

#[test]
fn test_protected_processes() {
    let config = ResponseConfig::default();
    let executor = ResponseExecutor::new(config).unwrap();

    assert!(executor.is_protected_process(1)); // init
    assert!(executor.is_protected_process(2)); // kthreadd
}

#[test]
fn test_protected_system_paths() {
    let config = ResponseConfig::default();
    let executor = ResponseExecutor::new(config).unwrap();

    // System directories should be protected
    assert!(executor.is_protected_path(Path::new("/usr/bin/ls")));
    assert!(executor.is_protected_path(Path::new("/sbin/init")));
    assert!(executor.is_protected_path(Path::new("/lib/libc.so.6")));
}
