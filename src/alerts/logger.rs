//! Alert Logger
//!
//! Handles alert output to various destinations.

use parking_lot::Mutex;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::error;

use crate::config::AlertsConfig;
use crate::detection::{Detection, Severity};
use crate::{EdrError, Result};

use super::Alert;

/// Alert logger
pub struct AlertLogger {
    /// Configuration
    config: AlertsConfig,
    /// File writer (if output is file)
    file_writer: Option<Arc<Mutex<BufWriter<File>>>>,
}

impl AlertLogger {
    /// Create a new alert logger
    pub fn new(config: AlertsConfig) -> Result<Self> {
        let file_writer = if config.output.to_lowercase() == "file" {
            // Create parent directory if needed
            if let Some(parent) = config.file_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&config.file_path)
                .map_err(|e| {
                    EdrError::Config(format!(
                        "Failed to open alert file {:?}: {}",
                        config.file_path, e
                    ))
                })?;

            Some(Arc::new(Mutex::new(BufWriter::new(file))))
        } else {
            None
        };

        Ok(Self {
            config,
            file_writer,
        })
    }

    /// Log a detection
    pub fn log_detection(&self, detection: &Detection) -> Result<()> {
        // Check severity threshold
        let threshold = Severity::parse(&self.config.severity_threshold);
        if detection.severity < threshold {
            return Ok(());
        }

        // Convert to alert
        let alert: Alert = detection.clone().into();

        // Output based on configuration
        match self.config.output.to_lowercase().as_str() {
            "file" => self.write_to_file(&alert)?,
            "stdout" => self.write_to_stdout(&alert)?,
            "syslog" => self.write_to_syslog(&alert)?,
            _ => self.write_to_stdout(&alert)?,
        }

        Ok(())
    }

    /// Log an alert
    pub fn log_alert(&self, alert: &Alert) -> Result<()> {
        // Check severity threshold
        let threshold = Severity::parse(&self.config.severity_threshold);
        if alert.severity < threshold {
            return Ok(());
        }

        match self.config.output.to_lowercase().as_str() {
            "file" => self.write_to_file(alert)?,
            "stdout" => self.write_to_stdout(alert)?,
            "syslog" => self.write_to_syslog(alert)?,
            _ => self.write_to_stdout(alert)?,
        }

        Ok(())
    }

    /// Write alert to file
    fn write_to_file(&self, alert: &Alert) -> Result<()> {
        if let Some(writer) = &self.file_writer {
            let json = serde_json::to_string(alert)
                .map_err(|e| EdrError::Config(format!("Failed to serialize alert: {e}")))?;

            let mut writer = writer.lock();
            writeln!(writer, "{json}")?;
            writer.flush()?;
        }

        Ok(())
    }

    /// Write alert to stdout
    fn write_to_stdout(&self, alert: &Alert) -> Result<()> {
        let severity_color = match alert.severity {
            Severity::Critical => "\x1b[91m", // Bright red
            Severity::High => "\x1b[31m",     // Red
            Severity::Medium => "\x1b[33m",   // Yellow
            Severity::Low => "\x1b[36m",      // Cyan
            Severity::Info => "\x1b[37m",     // White
        };

        let reset = "\x1b[0m";

        println!(
            "{}[{}]{} {} - {}",
            severity_color,
            alert.severity.as_str().to_uppercase(),
            reset,
            alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            alert.title
        );
        println!("  Target: {}", alert.target);
        println!("  Rules: {}", alert.matched_rules.join(", "));

        if let Some(hashes) = &alert.hashes {
            println!("  MD5: {}", hashes.md5);
            println!("  SHA256: {}", hashes.sha256);
        }

        if let Some(process) = &alert.process {
            println!("  Process: {} (PID: {})", process.name, process.pid);
            if let Some(cmdline) = &process.cmdline {
                println!("  Command: {cmdline}");
            }
        }

        if !alert.actions.is_empty() {
            println!("  Actions: {}", alert.actions.join(", "));
        }

        println!();

        Ok(())
    }

    /// Write alert to syslog
    fn write_to_syslog(&self, alert: &Alert) -> Result<()> {
        // Use logger command for syslog
        let priority = match alert.severity {
            Severity::Critical => "crit",
            Severity::High => "err",
            Severity::Medium => "warning",
            Severity::Low => "notice",
            Severity::Info => "info",
        };

        let message = format!(
            "yara-edr[{}]: {} - {} on {} (rules: {})",
            std::process::id(),
            alert.severity.as_str().to_uppercase(),
            alert.title,
            alert.target,
            alert.matched_rules.join(", ")
        );

        // Use the logger command to write to syslog
        let output = std::process::Command::new("logger")
            .args(["-p", &format!("local0.{priority}"), &message])
            .output();

        if let Err(e) = output {
            error!("Failed to write to syslog: {}", e);
        }

        Ok(())
    }

    /// Flush the logger
    pub fn flush(&self) -> Result<()> {
        if let Some(writer) = &self.file_writer {
            writer.lock().flush()?;
        }
        Ok(())
    }

    /// Get the alert file path
    pub fn file_path(&self) -> Option<&PathBuf> {
        if self.config.output.to_lowercase() == "file" {
            Some(&self.config.file_path)
        } else {
            None
        }
    }
}

impl Drop for AlertLogger {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// Create a summary report of detections
pub fn create_summary_report(detections: &[Detection]) -> String {
    let mut report = String::new();

    report.push_str("=== YARA-EDR Detection Summary ===\n\n");
    report.push_str(&format!("Total detections: {}\n", detections.len()));

    // Count by severity
    let critical = detections
        .iter()
        .filter(|d| d.severity == Severity::Critical)
        .count();
    let high = detections
        .iter()
        .filter(|d| d.severity == Severity::High)
        .count();
    let medium = detections
        .iter()
        .filter(|d| d.severity == Severity::Medium)
        .count();
    let low = detections
        .iter()
        .filter(|d| d.severity == Severity::Low)
        .count();
    let info = detections
        .iter()
        .filter(|d| d.severity == Severity::Info)
        .count();

    report.push_str("\nBy Severity:\n");
    report.push_str(&format!("  Critical: {critical}\n"));
    report.push_str(&format!("  High: {high}\n"));
    report.push_str(&format!("  Medium: {medium}\n"));
    report.push_str(&format!("  Low: {low}\n"));
    report.push_str(&format!("  Info: {info}\n"));

    // List detections
    if !detections.is_empty() {
        report.push_str("\nDetections:\n");
        for detection in detections {
            let rules: Vec<&str> = detection
                .scan_result
                .matches
                .iter()
                .map(|m| m.rule.as_str())
                .collect();

            report.push_str(&format!(
                "  [{:8}] {} - {}\n",
                detection.severity.as_str().to_uppercase(),
                detection.scan_result.target,
                rules.join(", ")
            ));
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_threshold() {
        let threshold = Severity::parse("medium");
        assert!(Severity::Critical >= threshold);
        assert!(Severity::High >= threshold);
        assert!(Severity::Medium >= threshold);
        assert!(Severity::Low < threshold);
        assert!(Severity::Info < threshold);
    }
}
