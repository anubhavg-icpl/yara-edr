//! Unit tests for process monitor.

use yara_edr::config::ProcessMonitorConfig;
use yara_edr::monitors::{ProcessEvent, ProcessMonitor};

#[test]
fn test_process_event_populate() {
    // Get current process info
    let pid = std::process::id() as i32;
    let mut event = ProcessEvent::new(pid);
    event.populate_from_proc();

    assert!(!event.name.is_empty());
    assert!(event.exe_path.is_some());
}

#[test]
fn test_is_excluded() {
    let config = ProcessMonitorConfig {
        exclude_pids: vec![100, 200],
        exclude_names: vec!["excluded_process".to_string()],
        ..Default::default()
    };

    let monitor = ProcessMonitor::new(config);

    assert!(monitor.is_excluded(100, "test"));
    assert!(monitor.is_excluded(300, "excluded_process"));
    assert!(!monitor.is_excluded(300, "normal_process"));
}

#[test]
fn test_process_event_new() {
    let event = ProcessEvent::new(1234);
    assert_eq!(event.pid, 1234);
    assert!(event.name.is_empty());
    assert!(event.exe_path.is_none());
}
