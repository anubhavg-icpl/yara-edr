//! Unit tests for file monitor.

use std::path::Path;
use yara_edr::config::FileMonitorConfig;
use yara_edr::monitors::FileMonitor;

#[test]
fn test_should_scan_file() {
    let config = FileMonitorConfig {
        extensions: vec!["exe".to_string(), "sh".to_string()],
        exclude_patterns: vec!["/tmp/*".to_string()],
        ..Default::default()
    };

    let monitor = FileMonitor::new(config).unwrap();

    assert!(monitor.should_scan_file(Path::new("/home/test.exe")));
    assert!(monitor.should_scan_file(Path::new("/home/script.sh")));
    assert!(!monitor.should_scan_file(Path::new("/home/test.txt")));
}

#[test]
fn test_file_monitor_empty_extensions() {
    // Empty extensions should scan all files
    let config = FileMonitorConfig {
        extensions: vec![],
        exclude_patterns: vec![],
        ..Default::default()
    };

    let monitor = FileMonitor::new(config).unwrap();

    assert!(monitor.should_scan_file(Path::new("/home/test.any")));
    assert!(monitor.should_scan_file(Path::new("/home/file")));
}
