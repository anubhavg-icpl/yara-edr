//! Alerts Module
//!
//! Provides logging and alerting functionality.

pub mod logger;

pub use logger::AlertLogger;

use serde::{Deserialize, Serialize};

use crate::detection::{Detection, Severity};

/// Alert structure for output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique alert ID
    pub id: uuid::Uuid,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Severity level
    pub severity: Severity,
    /// Alert title
    pub title: String,
    /// Alert description
    pub description: String,
    /// Target (file path, PID, etc.)
    pub target: String,
    /// Matched rules
    pub matched_rules: Vec<String>,
    /// File hashes (if applicable)
    pub hashes: Option<AlertHashes>,
    /// Process context (if applicable)
    pub process: Option<AlertProcess>,
    /// Recommended actions
    pub actions: Vec<String>,
}

/// File hashes in alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertHashes {
    pub md5: String,
    pub sha256: String,
}

/// Process information in alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertProcess {
    pub pid: i32,
    pub name: String,
    pub cmdline: Option<String>,
    pub exe_path: Option<String>,
    pub username: Option<String>,
}

impl From<Detection> for Alert {
    fn from(detection: Detection) -> Self {
        let matched_rules: Vec<String> = detection
            .scan_result
            .matches
            .iter()
            .map(|m| m.rule.clone())
            .collect();

        let title = format!(
            "{} severity detection: {} rule(s) matched",
            detection.severity,
            matched_rules.len()
        );

        let description = format!(
            "YARA rules matched on target: {}. Rules: {}",
            detection.scan_result.target,
            matched_rules.join(", ")
        );

        let hashes = detection.scan_result.hashes.map(|h| AlertHashes {
            md5: h.md5,
            sha256: h.sha256,
        });

        let process = detection.process_context.map(|p| AlertProcess {
            pid: p.pid,
            name: p.name,
            cmdline: p.cmdline,
            exe_path: p.exe_path.map(|e| e.to_string_lossy().to_string()),
            username: p.username,
        });

        let actions: Vec<String> = detection
            .recommended_actions
            .iter()
            .map(|a| format!("{:?}", a))
            .collect();

        Self {
            id: detection.id,
            timestamp: detection.timestamp,
            severity: detection.severity,
            title,
            description,
            target: detection.scan_result.target,
            matched_rules,
            hashes,
            process,
            actions,
        }
    }
}
