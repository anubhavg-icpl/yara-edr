//! Memory Scanner
//!
//! Provides process memory scanning capabilities.

use parking_lot::RwLock;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::config::ProcessMonitorConfig;
use crate::engine::{ScanResult, Scanner};
use crate::utils::process;
use crate::{EdrError, Result};

use super::{Detection, DetectionSource, ProcessContext, Severity};

/// Memory scanner for process scanning
pub struct MemoryScanner {
    /// YARA scanner
    scanner: Arc<RwLock<Scanner>>,
    /// Configuration
    config: ProcessMonitorConfig,
    /// Detection channel
    detection_tx: Option<mpsc::Sender<Detection>>,
}

impl MemoryScanner {
    /// Create a new memory scanner
    pub fn new(scanner: Arc<RwLock<Scanner>>, config: ProcessMonitorConfig) -> Self {
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

    /// Scan a process by PID
    pub fn scan_process(&self, pid: i32) -> Result<ScanResult> {
        // Check exclusions
        if self.config.exclude_pids.contains(&pid) {
            return Err(EdrError::Scan(format!("Process {} is excluded", pid)));
        }

        // Get process name for exclusion check
        if let Ok(process) = procfs::process::Process::new(pid) {
            if let Ok(stat) = process.stat() {
                if self.config.exclude_names.contains(&stat.comm) {
                    return Err(EdrError::Scan(format!(
                        "Process {} ({}) is excluded by name",
                        pid, stat.comm
                    )));
                }
            }
        }

        // Scan process using the scanner
        let scanner = self.scanner.read();
        scanner.scan_process(pid)
    }

    /// Scan process with detection
    pub async fn scan_process_with_detection(
        &self,
        pid: i32,
        source: DetectionSource,
    ) -> Result<Option<Detection>> {
        let result = self.scan_process(pid)?;

        if result.is_match {
            // Get process context
            let process_context = self.get_process_context(pid);

            let mut detection = Detection::new(result, source);

            if let Some(context) = process_context {
                detection = detection.with_process_context(context);
            }

            // Send detection
            if let Some(tx) = &self.detection_tx {
                if let Err(e) = tx.send(detection.clone()).await {
                    error!("Failed to send detection: {}", e);
                }
            }

            return Ok(Some(detection));
        }

        Ok(None)
    }

    /// Get process context information
    fn get_process_context(&self, pid: i32) -> Option<ProcessContext> {
        let process = procfs::process::Process::new(pid).ok()?;

        let stat = process.stat().ok()?;
        let status = process.status().ok();
        let cmdline = process.cmdline().ok();
        let exe = process.exe().ok();

        // Get username from UID
        let uid = status.as_ref().map(|s| s.ruid);
        let username = uid.and_then(|u| {
            nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(u))
                .ok()
                .flatten()
                .map(|user| user.name)
        });

        Some(ProcessContext {
            pid,
            ppid: Some(stat.ppid),
            name: stat.comm,
            cmdline: cmdline.map(|c| c.join(" ")),
            exe_path: exe,
            uid,
            username,
        })
    }

    /// Scan all running processes
    pub async fn scan_all_processes(&self) -> Result<ProcessScanSummary> {
        info!("Starting full process memory scan");

        let mut summary = ProcessScanSummary::default();

        // Get list of all PIDs
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();

            // Check if this is a PID directory
            if let Ok(pid) = name.parse::<i32>() {
                // Skip kernel threads
                if pid <= 2 {
                    continue;
                }

                summary.processes_scanned += 1;

                match self
                    .scan_process_with_detection(pid, DetectionSource::MemoryScan)
                    .await
                {
                    Ok(Some(detection)) => {
                        summary.detections += 1;
                        summary.detected_pids.push(pid);

                        match detection.severity {
                            Severity::Critical => summary.critical += 1,
                            Severity::High => summary.high += 1,
                            Severity::Medium => summary.medium += 1,
                            Severity::Low => summary.low += 1,
                            Severity::Info => summary.info += 1,
                        }
                    }
                    Ok(None) => {
                        // No detection
                    }
                    Err(e) => {
                        debug!("Failed to scan process {}: {}", pid, e);
                        summary.scan_errors += 1;
                    }
                }
            }
        }

        info!(
            "Process scan complete: {} scanned, {} detections, {} errors",
            summary.processes_scanned, summary.detections, summary.scan_errors
        );

        Ok(summary)
    }

    /// Scan specific memory regions of a process
    pub fn scan_process_regions(&self, pid: i32) -> Result<Vec<MemoryRegionScan>> {
        let regions = process::get_process_memory_regions(pid)?;
        let mut results = Vec::new();

        let scanner = self.scanner.read();

        for region in regions {
            // Skip non-readable regions
            if !region.permissions.contains('r') {
                continue;
            }

            // Read region data
            let size = (region.end - region.start) as usize;
            match process::read_memory_region(pid, region.start, size) {
                Ok(data) => {
                    let scan_result = scanner.scan_buffer(
                        &data,
                        &format!("pid:{}:0x{:x}-0x{:x}", pid, region.start, region.end),
                    )?;

                    results.push(MemoryRegionScan {
                        start: region.start,
                        end: region.end,
                        permissions: region.permissions.clone(),
                        pathname: region.pathname.clone(),
                        scan_result,
                    });
                }
                Err(e) => {
                    debug!(
                        "Failed to read memory region 0x{:x}-0x{:x}: {}",
                        region.start, region.end, e
                    );
                }
            }
        }

        Ok(results)
    }
}

/// Summary of a process scan operation
#[derive(Debug, Clone, Default)]
pub struct ProcessScanSummary {
    /// Number of processes scanned
    pub processes_scanned: usize,
    /// Number of detections
    pub detections: usize,
    /// PIDs with detections
    pub detected_pids: Vec<i32>,
    /// Number of scan errors
    pub scan_errors: usize,
    /// Severity counts
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl std::fmt::Display for ProcessScanSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Process Scan Summary:")?;
        writeln!(f, "  Processes scanned: {}", self.processes_scanned)?;
        writeln!(f, "  Detections: {}", self.detections)?;
        writeln!(f, "  Scan errors: {}", self.scan_errors)?;
        if self.detections > 0 {
            writeln!(f, "  Detected PIDs: {:?}", self.detected_pids)?;
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

/// Result of scanning a memory region
#[derive(Debug, Clone)]
pub struct MemoryRegionScan {
    /// Start address
    pub start: u64,
    /// End address
    pub end: u64,
    /// Permissions (rwxp)
    pub permissions: String,
    /// Pathname (if mapped file)
    pub pathname: Option<String>,
    /// Scan result
    pub scan_result: ScanResult,
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let display = format!("{}", summary);
        assert!(display.contains("Processes scanned: 100"));
        assert!(display.contains("Detections: 2"));
    }
}
