//! Unit tests for file scanner.

use yara_edr::detection::ScanSummary;

#[test]
fn test_scan_summary_display() {
    let summary = ScanSummary {
        files_scanned: 100,
        bytes_scanned: 1024 * 1024 * 50, // 50 MB
        detections: 3,
        matched_files: vec!["file1".to_string(), "file2".to_string()],
        critical: 1,
        high: 1,
        medium: 1,
        low: 0,
        info: 0,
    };

    let display = format!("{summary}");
    assert!(display.contains("Files scanned: 100"));
    assert!(display.contains("Detections: 3"));
}

#[test]
fn test_scan_summary_default() {
    let summary = ScanSummary::default();
    assert_eq!(summary.files_scanned, 0);
    assert_eq!(summary.bytes_scanned, 0);
    assert_eq!(summary.detections, 0);
    assert!(summary.matched_files.is_empty());
}

#[test]
fn test_scan_summary_bytes_display() {
    // Test various byte sizes
    let summary = ScanSummary {
        files_scanned: 1,
        bytes_scanned: 1024 * 1024 * 1024, // 1 GB
        detections: 0,
        matched_files: vec![],
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
    };

    let display = format!("{summary}");
    assert!(display.contains("Files scanned: 1"));
}
