//! Unit tests for memory scanner.

use yara_edr::detection::ProcessScanSummary;

#[test]
fn test_process_scan_summary_display() {
    let summary = ProcessScanSummary {
        processes_scanned: 100,
        detections: 2,
        detected_pids: vec![1234, 5678],
        scan_errors: 5,
        critical: 1,
        high: 1,
        medium: 0,
        low: 0,
        info: 0,
    };

    let display = format!("{summary}");
    assert!(display.contains("Processes scanned: 100"));
    assert!(display.contains("Detections: 2"));
}

#[test]
fn test_process_scan_summary_default() {
    let summary = ProcessScanSummary::default();
    assert_eq!(summary.processes_scanned, 0);
    assert_eq!(summary.detections, 0);
    assert!(summary.detected_pids.is_empty());
    assert_eq!(summary.scan_errors, 0);
}
