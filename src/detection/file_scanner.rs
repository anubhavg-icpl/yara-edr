//! File Scanner
//!
//! Provides file scanning capabilities with directory traversal.

use parking_lot::RwLock;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use walkdir::WalkDir;

use crate::config::FileMonitorConfig;
use crate::engine::{ScanResult, Scanner};
use crate::{EdrError, Result};

use super::{Detection, DetectionSource, Severity};

/// File scanner for on-demand and batch scanning
pub struct FileScanner {
    /// YARA scanner
    scanner: Arc<RwLock<Scanner>>,
    /// Configuration
    config: FileMonitorConfig,
    /// Detection channel
    detection_tx: Option<mpsc::Sender<Detection>>,
}

impl FileScanner {
    /// Create a new file scanner
    pub fn new(scanner: Arc<RwLock<Scanner>>, config: FileMonitorConfig) -> Self {
        Self {
            scanner,
            config,
            detection_tx: None,
        }
    }

    /// Set the detection channel
    pub fn set_detection_channel(&mut self, tx: mpsc::Sender<Detection>) {
        self.detection_tx = Some(tx);
    }

    /// Scan a single file
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<ScanResult> {
        let path = path.as_ref();

        // Validate file
        if !path.exists() {
            return Err(EdrError::Scan(format!("File not found: {path:?}")));
        }

        if !path.is_file() {
            return Err(EdrError::Scan(format!("Not a file: {path:?}")));
        }

        // Check file size
        if self.config.max_file_size > 0 {
            let metadata = std::fs::metadata(path)?;
            if metadata.len() > self.config.max_file_size {
                return Err(EdrError::Scan(format!(
                    "File too large: {:?} ({} bytes)",
                    path,
                    metadata.len()
                )));
            }
        }

        // Check exclusions
        if self.is_excluded(path) {
            return Err(EdrError::Scan(format!("File excluded: {path:?}")));
        }

        // Perform scan
        let scanner = self.scanner.read();
        scanner.scan_file(path)
    }

    /// Scan a file and send detection if matched
    pub async fn scan_file_with_detection<P: AsRef<Path>>(
        &self,
        path: P,
        source: DetectionSource,
    ) -> Result<Option<Detection>> {
        let result = self.scan_file(path)?;

        if result.is_match {
            let detection = Detection::new(result, source);

            // Send detection through channel
            if let Some(tx) = &self.detection_tx
                && let Err(e) = tx.send(detection.clone()).await
            {
                error!("Failed to send detection: {}", e);
            }

            return Ok(Some(detection));
        }

        Ok(None)
    }

    /// Scan a directory
    pub fn scan_directory<P: AsRef<Path>>(&self, path: P) -> Result<Vec<ScanResult>> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(EdrError::Scan(format!("Directory not found: {path:?}")));
        }

        if !path.is_dir() {
            return Err(EdrError::Scan(format!("Not a directory: {path:?}")));
        }

        let mut results = Vec::new();

        let walker = if self.config.recursive {
            WalkDir::new(path)
        } else {
            WalkDir::new(path).max_depth(1)
        };

        for entry in walker.into_iter().filter_map(std::result::Result::ok) {
            let entry_path = entry.path();

            // Skip directories
            if entry_path.is_dir() {
                continue;
            }

            // Check if should scan this file
            if !self.should_scan_file(entry_path) {
                continue;
            }

            match self.scan_file(entry_path) {
                Ok(result) => {
                    if result.is_match {
                        info!(
                            "Detection in {:?}: {} rule(s) matched",
                            entry_path,
                            result.matches.len()
                        );
                    }
                    results.push(result);
                },
                Err(e) => {
                    debug!("Failed to scan {:?}: {}", entry_path, e);
                },
            }
        }

        Ok(results)
    }

    /// Scan directory with detection events
    pub async fn scan_directory_with_detections<P: AsRef<Path>>(
        &self,
        path: P,
        source: DetectionSource,
    ) -> Result<ScanSummary> {
        let results = self.scan_directory(path)?;

        let mut summary = ScanSummary::default();

        for result in results {
            summary.files_scanned += 1;
            summary.bytes_scanned += result.size;

            if result.is_match {
                summary.detections += 1;
                summary.matched_files.push(result.target.clone());

                let detection = Detection::new(result, source.clone());

                // Update severity counts
                match detection.severity {
                    Severity::Critical => summary.critical += 1,
                    Severity::High => summary.high += 1,
                    Severity::Medium => summary.medium += 1,
                    Severity::Low => summary.low += 1,
                    Severity::Info => summary.info += 1,
                }

                // Send detection
                if let Some(tx) = &self.detection_tx
                    && let Err(e) = tx.send(detection).await
                {
                    error!("Failed to send detection: {}", e);
                }
            }
        }

        Ok(summary)
    }

    /// Check if file should be scanned based on extension
    fn should_scan_file(&self, path: &Path) -> bool {
        // Check exclusions
        if self.is_excluded(path) {
            return false;
        }

        // Check file size
        if self.config.max_file_size > 0
            && let Ok(metadata) = std::fs::metadata(path)
            && metadata.len() > self.config.max_file_size
        {
            return false;
        }

        // If no extensions specified, scan all files
        if self.config.extensions.is_empty() {
            return true;
        }

        // Check extension
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            return self
                .config
                .extensions
                .iter()
                .any(|e| e.to_lowercase() == ext_str);
        }

        false
    }

    /// Check if path matches exclusion patterns
    fn is_excluded(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        for pattern in &self.config.exclude_patterns {
            if let Ok(glob_pattern) = glob::Pattern::new(pattern)
                && glob_pattern.matches(&path_str)
            {
                return true;
            }
        }

        false
    }
}

/// Summary of a scan operation
#[derive(Debug, Clone, Default)]
pub struct ScanSummary {
    /// Number of files scanned
    pub files_scanned: usize,
    /// Total bytes scanned
    pub bytes_scanned: u64,
    /// Number of detections
    pub detections: usize,
    /// List of files with detections
    pub matched_files: Vec<String>,
    /// Critical severity count
    pub critical: usize,
    /// High severity count
    pub high: usize,
    /// Medium severity count
    pub medium: usize,
    /// Low severity count
    pub low: usize,
    /// Info severity count
    pub info: usize,
}

impl std::fmt::Display for ScanSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Scan Summary:")?;
        writeln!(f, "  Files scanned: {}", self.files_scanned)?;
        writeln!(
            f,
            "  Bytes scanned: {} MB",
            self.bytes_scanned / 1024 / 1024
        )?;
        writeln!(f, "  Detections: {}", self.detections)?;
        if self.detections > 0 {
            writeln!(f, "  Severity breakdown:")?;
            writeln!(f, "    Critical: {}", self.critical)?;
            writeln!(f, "    High: {}", self.high)?;
            writeln!(f, "    Medium: {}", self.medium)?;
            writeln!(f, "    Low: {}", self.low)?;
            writeln!(f, "    Info: {}", self.info)?;
        }
        Ok(())
    }
}

/// Batch scanner for scanning multiple paths
pub struct BatchScanner {
    file_scanner: FileScanner,
}

impl BatchScanner {
    pub fn new(file_scanner: FileScanner) -> Self {
        Self { file_scanner }
    }

    /// Scan multiple paths
    pub async fn scan_paths<P: AsRef<Path>>(&self, paths: &[P]) -> Result<ScanSummary> {
        let mut total_summary = ScanSummary::default();

        for path in paths {
            let path = path.as_ref();

            let summary = if path.is_dir() {
                self.file_scanner
                    .scan_directory_with_detections(path, DetectionSource::OnDemandScan)
                    .await?
            } else if path.is_file() {
                let result = self.file_scanner.scan_file(path)?;
                let mut summary = ScanSummary::default();
                summary.files_scanned = 1;
                summary.bytes_scanned = result.size;
                if result.is_match {
                    summary.detections = 1;
                    summary.matched_files.push(result.target);
                }
                summary
            } else {
                continue;
            };

            // Aggregate summaries
            total_summary.files_scanned += summary.files_scanned;
            total_summary.bytes_scanned += summary.bytes_scanned;
            total_summary.detections += summary.detections;
            total_summary.matched_files.extend(summary.matched_files);
            total_summary.critical += summary.critical;
            total_summary.high += summary.high;
            total_summary.medium += summary.medium;
            total_summary.low += summary.low;
            total_summary.info += summary.info;
        }

        Ok(total_summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let display = format!("{}", summary);
        assert!(display.contains("Files scanned: 100"));
        assert!(display.contains("Detections: 3"));
    }
}
