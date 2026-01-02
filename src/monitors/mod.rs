//! Monitoring Module
//!
//! This module provides file system and process monitoring capabilities.

pub mod file_monitor;
pub mod process_monitor;

pub use file_monitor::FileMonitor;
pub use process_monitor::ProcessMonitor;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Event types from monitors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MonitorEvent {
    /// File was created
    FileCreated(FileEvent),
    /// File was modified
    FileModified(FileEvent),
    /// File was deleted
    FileDeleted(FileEvent),
    /// File was renamed
    FileRenamed { from: PathBuf, to: PathBuf },
    /// New process started
    ProcessStarted(ProcessEvent),
    /// Process exited
    ProcessExited(ProcessEvent),
}

/// File event details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    /// Path to the file
    pub path: PathBuf,
    /// File size (if available)
    pub size: Option<u64>,
    /// Event timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Process event details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    /// Process ID
    pub pid: i32,
    /// Parent process ID
    pub ppid: Option<i32>,
    /// Process name
    pub name: String,
    /// Command line
    pub cmdline: Option<String>,
    /// Executable path
    pub exe_path: Option<PathBuf>,
    /// User ID
    pub uid: Option<u32>,
    /// Event timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl FileEvent {
    pub fn new(path: PathBuf) -> Self {
        let size = std::fs::metadata(&path).ok().map(|m| m.len());

        Self {
            path,
            size,
            timestamp: chrono::Utc::now(),
        }
    }
}

impl ProcessEvent {
    pub fn new(pid: i32) -> Self {
        Self {
            pid,
            ppid: None,
            name: String::new(),
            cmdline: None,
            exe_path: None,
            uid: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Populate process details from /proc
    pub fn populate_from_proc(&mut self) {
        if let Ok(process) = procfs::process::Process::new(self.pid) {
            // Get process name
            if let Ok(stat) = process.stat() {
                self.name = stat.comm;
                self.ppid = Some(stat.ppid);
            }

            // Get command line
            if let Ok(cmdline) = process.cmdline() {
                self.cmdline = Some(cmdline.join(" "));
            }

            // Get executable path
            if let Ok(exe) = process.exe() {
                self.exe_path = Some(exe);
            }

            // Get UID
            if let Ok(status) = process.status() {
                self.uid = Some(status.ruid);
            }
        }
    }
}
