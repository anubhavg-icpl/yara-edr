//! Unit tests for detection severity levels.

use yara_edr::detection::Severity;

#[test]
fn test_severity_ordering() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
}

#[test]
fn test_severity_parse() {
    assert_eq!(Severity::parse("critical"), Severity::Critical);
    assert_eq!(Severity::parse("HIGH"), Severity::High);
    assert_eq!(Severity::parse("medium"), Severity::Medium);
    assert_eq!(Severity::parse("low"), Severity::Low);
    assert_eq!(Severity::parse("info"), Severity::Info);
    assert_eq!(Severity::parse("unknown"), Severity::Info);
}

#[test]
fn test_severity_as_str() {
    assert_eq!(Severity::Critical.as_str(), "critical");
    assert_eq!(Severity::High.as_str(), "high");
    assert_eq!(Severity::Medium.as_str(), "medium");
    assert_eq!(Severity::Low.as_str(), "low");
    assert_eq!(Severity::Info.as_str(), "info");
}

#[test]
fn test_severity_display() {
    assert_eq!(format!("{}", Severity::Critical), "critical");
    assert_eq!(format!("{}", Severity::High), "high");
}

#[test]
fn test_severity_threshold() {
    let threshold = Severity::parse("medium");
    assert!(Severity::Critical >= threshold);
    assert!(Severity::High >= threshold);
    assert!(Severity::Medium >= threshold);
    assert!(Severity::Low < threshold);
    assert!(Severity::Info < threshold);
}
