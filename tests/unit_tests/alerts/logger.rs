//! Unit tests for alert logger.

use yara_edr::detection::Severity;

#[test]
fn test_severity_threshold() {
    let threshold = Severity::parse("medium");
    assert!(Severity::Critical >= threshold);
    assert!(Severity::High >= threshold);
    assert!(Severity::Medium >= threshold);
    assert!(Severity::Low < threshold);
    assert!(Severity::Info < threshold);
}

#[test]
fn test_severity_threshold_critical() {
    let threshold = Severity::parse("critical");
    assert!(Severity::Critical >= threshold);
    assert!(Severity::High < threshold);
}

#[test]
fn test_severity_threshold_info() {
    let threshold = Severity::parse("info");
    // All severities should be >= info
    assert!(Severity::Critical >= threshold);
    assert!(Severity::High >= threshold);
    assert!(Severity::Medium >= threshold);
    assert!(Severity::Low >= threshold);
    assert!(Severity::Info >= threshold);
}
