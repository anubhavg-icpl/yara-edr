//! Unit tests for YARA scanner.

use yara_edr::engine::{ScanResult, ScanType};

#[test]
fn test_scan_result_serialization() {
    let result = ScanResult {
        target: "/tmp/test".to_string(),
        scan_type: ScanType::File,
        matches: vec![],
        duration_ms: 100,
        timestamp: chrono::Utc::now(),
        is_match: false,
        size: 1024,
        hashes: None,
    };

    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("/tmp/test"));
}

#[test]
fn test_scan_type_debug() {
    // ScanType uses Debug, not Display
    assert!(format!("{:?}", ScanType::File).contains("File"));
    assert!(format!("{:?}", ScanType::Memory).contains("Memory"));
    assert!(format!("{:?}", ScanType::Buffer).contains("Buffer"));
}
