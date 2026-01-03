//! Response Actions
//!
//! Implements response actions for detected threats.

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

use crate::Result;
use crate::config::ResponseConfig;
use crate::detection::Detection;

use super::QuarantineManager;

/// Available response actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseAction {
    /// Quarantine a file
    Quarantine { path: PathBuf },
    /// Delete a file
    Delete { path: PathBuf },
    /// Kill a process
    KillProcess { pid: i32 },
    /// Suspend a process
    SuspendProcess { pid: i32 },
    /// Log the detection (no action)
    LogOnly,
    /// Block network access for a process (requires additional setup)
    BlockNetwork { pid: i32 },
}

/// Result of executing a response action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    /// The action that was executed
    pub action: ResponseAction,
    /// Whether the action was successful
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ActionResult {
    pub fn success(action: ResponseAction) -> Self {
        Self {
            action,
            success: true,
            error: None,
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn failure(action: ResponseAction, error: String) -> Self {
        Self {
            action,
            success: false,
            error: Some(error),
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Executes response actions
pub struct ResponseExecutor {
    /// Configuration
    config: ResponseConfig,
    /// Quarantine manager
    quarantine: parking_lot::RwLock<QuarantineManager>,
}

impl ResponseExecutor {
    /// Create a new response executor
    pub fn new(config: ResponseConfig) -> Result<Self> {
        let quarantine = QuarantineManager::new(config.quarantine_path.clone())?;

        Ok(Self {
            config,
            quarantine: parking_lot::RwLock::new(quarantine),
        })
    }

    /// Execute a response action
    pub fn execute(&self, action: ResponseAction) -> ActionResult {
        info!("Executing response action: {:?}", action);

        match action {
            ResponseAction::Quarantine { path } => self.quarantine_file(&path),
            ResponseAction::Delete { path } => self.delete_file(&path),
            ResponseAction::KillProcess { pid } => self.kill_process(pid),
            ResponseAction::SuspendProcess { pid } => self.suspend_process(pid),
            ResponseAction::LogOnly => ActionResult::success(ResponseAction::LogOnly),
            ResponseAction::BlockNetwork { pid } => {
                warn!("Network blocking not implemented");
                ActionResult::failure(
                    ResponseAction::BlockNetwork { pid },
                    "Not implemented".to_string(),
                )
            },
        }
    }

    /// Execute automatic response based on detection
    pub fn execute_automatic(&self, detection: &Detection) -> Vec<ActionResult> {
        let mut results = Vec::new();

        // Check if auto-quarantine is enabled
        if self.config.auto_quarantine {
            // Get file path from detection
            if let Some(path) = self.extract_file_path(detection) {
                let action = ResponseAction::Quarantine {
                    path: PathBuf::from(path),
                };
                results.push(self.execute(action));
            }
        }

        // Check if auto-kill is enabled
        if self.config.auto_kill
            && let Some(context) = &detection.process_context
        {
            let action = ResponseAction::KillProcess { pid: context.pid };
            results.push(self.execute(action));
        }

        results
    }

    /// Quarantine a file
    fn quarantine_file(&self, path: &Path) -> ActionResult {
        let action = ResponseAction::Quarantine {
            path: path.to_path_buf(),
        };
        match self.quarantine.write().quarantine_file(path) {
            Ok(entry) => {
                info!(
                    "File quarantined: {:?} -> {:?}",
                    path, entry.quarantine_path
                );
                ActionResult::success(action)
            },
            Err(e) => {
                error!("Failed to quarantine file {:?}: {}", path, e);
                ActionResult::failure(action, e.to_string())
            },
        }
    }

    /// Delete a file
    fn delete_file(&self, path: &Path) -> ActionResult {
        let action = ResponseAction::Delete {
            path: path.to_path_buf(),
        };
        // Safety check: don't delete system files
        if self.is_protected_path(path) {
            return ActionResult::failure(
                action,
                "Cannot delete protected system file".to_string(),
            );
        }

        match std::fs::remove_file(path) {
            Ok(()) => {
                info!("File deleted: {:?}", path);
                ActionResult::success(action)
            },
            Err(e) => {
                error!("Failed to delete file {:?}: {}", path, e);
                ActionResult::failure(action, e.to_string())
            },
        }
    }

    /// Kill a process
    fn kill_process(&self, pid: i32) -> ActionResult {
        let action = ResponseAction::KillProcess { pid };
        // Safety check: don't kill critical system processes
        if self.is_protected_process(pid) {
            return ActionResult::failure(
                action,
                "Cannot kill protected system process".to_string(),
            );
        }

        match kill(Pid::from_raw(pid), Signal::SIGKILL) {
            Ok(()) => {
                info!("Process killed: PID {}", pid);
                ActionResult::success(action)
            },
            Err(e) => {
                error!("Failed to kill process {}: {}", pid, e);
                ActionResult::failure(action, e.to_string())
            },
        }
    }

    /// Suspend a process
    fn suspend_process(&self, pid: i32) -> ActionResult {
        let action = ResponseAction::SuspendProcess { pid };
        if self.is_protected_process(pid) {
            return ActionResult::failure(
                action,
                "Cannot suspend protected system process".to_string(),
            );
        }

        match kill(Pid::from_raw(pid), Signal::SIGSTOP) {
            Ok(()) => {
                info!("Process suspended: PID {}", pid);
                ActionResult::success(action)
            },
            Err(e) => {
                error!("Failed to suspend process {}: {}", pid, e);
                ActionResult::failure(action, e.to_string())
            },
        }
    }

    /// Check if a path is protected
    fn is_protected_path(&self, path: &Path) -> bool {
        let protected_prefixes = [
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/lib",
            "/lib64",
            "/usr/lib",
            "/etc",
            "/boot",
            "/proc",
            "/sys",
            "/dev",
        ];

        let path_str = path.to_string_lossy();

        for prefix in &protected_prefixes {
            if path_str.starts_with(prefix) {
                return true;
            }
        }

        false
    }

    /// Check if a process is protected
    fn is_protected_process(&self, pid: i32) -> bool {
        // Never kill init or kernel processes
        if pid <= 2 {
            return true;
        }

        // Check if it's a system process
        if let Ok(process) = procfs::process::Process::new(pid)
            && let Ok(stat) = process.stat()
        {
            let protected_names = ["systemd", "init", "kernel", "kthreadd"];
            if protected_names.contains(&stat.comm.as_str()) {
                return true;
            }
        }

        false
    }

    /// Extract file path from detection
    fn extract_file_path<'a>(&self, detection: &'a Detection) -> Option<&'a str> {
        // Check if the target looks like a file path
        let target = &detection.scan_result.target;

        if target.starts_with('/') && !target.starts_with("/proc") {
            return Some(target);
        }

        // Check process context for exe path
        if let Some(context) = &detection.process_context
            && let Some(exe_path) = &context.exe_path
        {
            return Some(exe_path.to_str().unwrap_or(""));
        }

        None
    }

    /// Get quarantine manager
    pub fn quarantine(&self) -> &parking_lot::RwLock<QuarantineManager> {
        &self.quarantine
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protected_paths() {
        let config = ResponseConfig::default();
        let executor = ResponseExecutor::new(config).unwrap();

        assert!(executor.is_protected_path(Path::new("/bin/bash")));
        assert!(executor.is_protected_path(Path::new("/etc/passwd")));
        assert!(!executor.is_protected_path(Path::new("/tmp/malware")));
        assert!(!executor.is_protected_path(Path::new("/home/user/file")));
    }

    #[test]
    fn test_protected_processes() {
        let config = ResponseConfig::default();
        let executor = ResponseExecutor::new(config).unwrap();

        assert!(executor.is_protected_process(1)); // init
        assert!(executor.is_protected_process(2)); // kthreadd
    }
}
