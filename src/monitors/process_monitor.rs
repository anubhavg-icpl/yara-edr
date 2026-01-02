//! Process Monitor
//!
//! Monitors process events on Linux using /proc filesystem.

use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::config::ProcessMonitorConfig;
use crate::{EdrError, Result};

use super::{MonitorEvent, ProcessEvent};

/// Process monitor
pub struct ProcessMonitor {
    /// Configuration
    config: ProcessMonitorConfig,
    /// Known process IDs
    known_pids: Arc<RwLock<HashSet<i32>>>,
    /// Event sender channel
    event_tx: Option<mpsc::Sender<MonitorEvent>>,
    /// Running flag
    running: Arc<RwLock<bool>>,
}

impl ProcessMonitor {
    /// Create a new process monitor
    pub fn new(config: ProcessMonitorConfig) -> Self {
        Self {
            config,
            known_pids: Arc::new(RwLock::new(HashSet::new())),
            event_tx: None,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Set the event sender channel
    pub fn set_event_channel(&mut self, tx: mpsc::Sender<MonitorEvent>) {
        self.event_tx = Some(tx);
    }

    /// Initialize the process monitor
    pub fn initialize(&mut self) -> Result<()> {
        info!("Initializing process monitor");

        // Populate known PIDs
        self.refresh_known_pids()?;

        info!(
            "Process monitor initialized with {} known processes",
            self.known_pids.read().len()
        );

        Ok(())
    }

    /// Refresh the list of known PIDs
    fn refresh_known_pids(&self) -> Result<()> {
        let mut known_pids = self.known_pids.write();
        known_pids.clear();

        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();

            // Check if this is a PID directory
            if let Ok(pid) = name.parse::<i32>() {
                known_pids.insert(pid);
            }
        }

        Ok(())
    }

    /// Get current PIDs from /proc
    fn get_current_pids(&self) -> Result<HashSet<i32>> {
        let mut pids = HashSet::new();

        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();

            if let Ok(pid) = name.parse::<i32>() {
                pids.insert(pid);
            }
        }

        Ok(pids)
    }

    /// Check if a PID should be excluded
    fn is_excluded(&self, pid: i32, name: &str) -> bool {
        // Check excluded PIDs
        if self.config.exclude_pids.contains(&pid) {
            return true;
        }

        // Check excluded names
        if self.config.exclude_names.iter().any(|n| n == name) {
            return true;
        }

        // Skip kernel threads (PID 2 and its children typically)
        if pid <= 2 {
            return true;
        }

        false
    }

    /// Start monitoring processes
    pub async fn start(
        &mut self,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<()> {
        info!("Starting process monitor");

        *self.running.write() = true;

        // Polling interval for checking new processes
        let poll_interval = Duration::from_millis(500);
        let mut interval = tokio::time::interval(poll_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.check_processes().await {
                        error!("Error checking processes: {}", e);
                    }
                }
                _ = shutdown.recv() => {
                    info!("Process monitor shutting down");
                    break;
                }
            }

            if !*self.running.read() {
                break;
            }
        }

        *self.running.write() = false;
        Ok(())
    }

    /// Check for new and exited processes
    async fn check_processes(&self) -> Result<()> {
        let current_pids = self.get_current_pids()?;
        let known_pids = self.known_pids.read().clone();

        // Find new processes
        let new_pids: Vec<i32> = current_pids.difference(&known_pids).copied().collect();

        // Find exited processes
        let exited_pids: Vec<i32> = known_pids.difference(&current_pids).copied().collect();

        // Handle new processes
        for pid in new_pids {
            if let Err(e) = self.handle_new_process(pid).await {
                debug!("Error handling new process {}: {}", pid, e);
            }
        }

        // Handle exited processes
        for pid in exited_pids {
            self.handle_exited_process(pid).await;
        }

        // Update known PIDs
        *self.known_pids.write() = current_pids;

        Ok(())
    }

    /// Handle a new process
    async fn handle_new_process(&self, pid: i32) -> Result<()> {
        let mut event = ProcessEvent::new(pid);
        event.populate_from_proc();

        // Check exclusions
        if self.is_excluded(pid, &event.name) {
            return Ok(());
        }

        debug!(
            "New process detected: {} (PID: {}, exe: {:?})",
            event.name, pid, event.exe_path
        );

        // Send event
        if let Some(tx) = &self.event_tx {
            let monitor_event = MonitorEvent::ProcessStarted(event);
            if let Err(e) = tx.send(monitor_event).await {
                error!("Failed to send process event: {}", e);
            }
        }

        Ok(())
    }

    /// Handle an exited process
    async fn handle_exited_process(&self, pid: i32) {
        debug!("Process exited: PID {}", pid);

        let event = ProcessEvent {
            pid,
            ppid: None,
            name: String::new(),
            cmdline: None,
            exe_path: None,
            uid: None,
            timestamp: chrono::Utc::now(),
        };

        // Send event
        if let Some(tx) = &self.event_tx {
            let monitor_event = MonitorEvent::ProcessExited(event);
            if let Err(e) = tx.send(monitor_event).await {
                error!("Failed to send process exit event: {}", e);
            }
        }
    }

    /// Get process details by PID
    pub fn get_process_info(pid: i32) -> Result<ProcessEvent> {
        let mut event = ProcessEvent::new(pid);
        event.populate_from_proc();

        if event.name.is_empty() {
            return Err(EdrError::ProcessMonitor(format!(
                "Process {} not found",
                pid
            )));
        }

        Ok(event)
    }

    /// List all current processes
    pub fn list_processes(&self) -> Result<Vec<ProcessEvent>> {
        let pids = self.get_current_pids()?;
        let mut processes = Vec::new();

        for pid in pids {
            let mut event = ProcessEvent::new(pid);
            event.populate_from_proc();

            if !event.name.is_empty() {
                processes.push(event);
            }
        }

        Ok(processes)
    }

    /// Stop monitoring
    pub fn stop(&mut self) {
        info!("Stopping process monitor");
        *self.running.write() = false;
    }

    /// Check if monitor is running
    pub fn is_running(&self) -> bool {
        *self.running.read()
    }

    /// Get count of known processes
    pub fn process_count(&self) -> usize {
        self.known_pids.read().len()
    }
}

impl Drop for ProcessMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Start process monitoring task
pub async fn start_process_monitor(
    config: ProcessMonitorConfig,
    event_tx: mpsc::Sender<MonitorEvent>,
    shutdown: tokio::sync::broadcast::Receiver<()>,
) -> Result<()> {
    let mut monitor = ProcessMonitor::new(config);
    monitor.set_event_channel(event_tx);
    monitor.initialize()?;
    monitor.start(shutdown).await
}

/// Periodic process scanner
pub struct PeriodicProcessScanner {
    config: ProcessMonitorConfig,
    scanner_tx: mpsc::Sender<i32>,
}

impl PeriodicProcessScanner {
    pub fn new(config: ProcessMonitorConfig, scanner_tx: mpsc::Sender<i32>) -> Self {
        Self { config, scanner_tx }
    }

    /// Start periodic scanning
    pub async fn start(&self, mut shutdown: tokio::sync::broadcast::Receiver<()>) -> Result<()> {
        let interval = Duration::from_secs(self.config.scan_interval);
        let mut timer = tokio::time::interval(interval);

        info!(
            "Starting periodic process scanner with interval: {:?}",
            interval
        );

        loop {
            tokio::select! {
                _ = timer.tick() => {
                    if let Err(e) = self.scan_all_processes().await {
                        error!("Error in periodic process scan: {}", e);
                    }
                }
                _ = shutdown.recv() => {
                    info!("Periodic process scanner shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Scan all running processes
    async fn scan_all_processes(&self) -> Result<()> {
        info!("Starting periodic scan of all processes");

        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();

            if let Ok(pid) = name.parse::<i32>() {
                // Skip excluded PIDs
                if self.config.exclude_pids.contains(&pid) {
                    continue;
                }

                // Send PID to scanner
                if let Err(e) = self.scanner_tx.send(pid).await {
                    debug!("Scanner channel closed: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_event_populate() {
        // Get current process info
        let pid = std::process::id() as i32;
        let mut event = ProcessEvent::new(pid);
        event.populate_from_proc();

        assert!(!event.name.is_empty());
        assert!(event.exe_path.is_some());
    }

    #[test]
    fn test_is_excluded() {
        let config = ProcessMonitorConfig {
            exclude_pids: vec![100, 200],
            exclude_names: vec!["excluded_process".to_string()],
            ..Default::default()
        };

        let monitor = ProcessMonitor::new(config);

        assert!(monitor.is_excluded(100, "test"));
        assert!(monitor.is_excluded(300, "excluded_process"));
        assert!(!monitor.is_excluded(300, "normal_process"));
    }
}
