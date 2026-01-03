//! Detection Module
//!
//! Provides file and memory scanning capabilities using YARA.

pub mod file_scanner;
pub mod memory_scanner;

pub use file_scanner::FileScanner;
pub use memory_scanner::MemoryScanner;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::engine::ScanResult;

/// Detection event with full context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// Unique detection ID
    pub id: uuid::Uuid,
    /// Scan result
    pub scan_result: ScanResult,
    /// Severity level
    pub severity: Severity,
    /// Detection source
    pub source: DetectionSource,
    /// Process context (if applicable)
    pub process_context: Option<ProcessContext>,
    /// Recommended actions
    pub recommended_actions: Vec<RecommendedAction>,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Severity level of a detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Parse severity from string
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Source of the detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionSource {
    /// File monitoring detected the file
    FileMonitor { event_type: String },
    /// Process monitoring detected the process
    ProcessMonitor { event_type: String },
    /// On-demand scan
    OnDemandScan,
    /// Scheduled scan
    ScheduledScan,
    /// Memory scan
    MemoryScan,
}

/// Process context for detections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    pub pid: i32,
    pub ppid: Option<i32>,
    pub name: String,
    pub cmdline: Option<String>,
    pub exe_path: Option<PathBuf>,
    pub uid: Option<u32>,
    pub username: Option<String>,
}

/// Recommended response action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendedAction {
    /// Quarantine the file
    Quarantine,
    /// Delete the file
    Delete,
    /// Kill the process
    KillProcess,
    /// Alert only (no action)
    AlertOnly,
    /// Manual review recommended
    ManualReview,
    /// Block execution
    BlockExecution,
}

impl Detection {
    /// Create a new detection from a scan result
    pub fn new(scan_result: ScanResult, source: DetectionSource) -> Self {
        let severity = Self::determine_severity(&scan_result);
        let recommended_actions = Self::determine_actions(&scan_result, &severity);

        Self {
            id: uuid::Uuid::new_v4(),
            scan_result,
            severity,
            source,
            process_context: None,
            recommended_actions,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create detection with process context
    pub fn with_process_context(mut self, context: ProcessContext) -> Self {
        self.process_context = Some(context);
        self
    }

    /// Determine severity based on rule metadata
    fn determine_severity(scan_result: &ScanResult) -> Severity {
        let mut max_severity = Severity::Info;

        for yara_match in &scan_result.matches {
            for (key, value) in &yara_match.metadata {
                if key.to_lowercase() == "severity" {
                    let severity = Severity::parse(value);
                    if severity > max_severity {
                        max_severity = severity;
                    }
                }
            }

            // Check for common threat indicators in rule names
            let rule_lower = yara_match.rule.to_lowercase();
            if rule_lower.contains("critical") || rule_lower.contains("ransomware") {
                if Severity::Critical > max_severity {
                    max_severity = Severity::Critical;
                }
            } else if rule_lower.contains("trojan") || rule_lower.contains("backdoor") {
                if Severity::High > max_severity {
                    max_severity = Severity::High;
                }
            } else if (rule_lower.contains("suspicious") || rule_lower.contains("packed"))
                && Severity::Medium > max_severity
            {
                max_severity = Severity::Medium;
            }
        }

        // Default to medium if matches exist but no severity found
        if max_severity == Severity::Info && !scan_result.matches.is_empty() {
            max_severity = Severity::Medium;
        }

        max_severity
    }

    /// Determine recommended actions based on severity and scan result
    fn determine_actions(_scan_result: &ScanResult, severity: &Severity) -> Vec<RecommendedAction> {
        let mut actions = Vec::new();

        match severity {
            Severity::Critical => {
                actions.push(RecommendedAction::Quarantine);
                actions.push(RecommendedAction::KillProcess);
            },
            Severity::High => {
                actions.push(RecommendedAction::Quarantine);
                actions.push(RecommendedAction::ManualReview);
            },
            Severity::Medium => {
                actions.push(RecommendedAction::AlertOnly);
                actions.push(RecommendedAction::ManualReview);
            },
            Severity::Low | Severity::Info => {
                actions.push(RecommendedAction::AlertOnly);
            },
        }

        actions
    }

    /// Get matched rule names
    pub fn matched_rules(&self) -> Vec<&str> {
        self.scan_result
            .matches
            .iter()
            .map(|m| m.rule.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::ScanType;

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
        assert_eq!(Severity::parse("unknown"), Severity::Info);
    }
}
