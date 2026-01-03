//! Daemon Mode
//!
//! Implements the background service functionality.

use parking_lot::RwLock;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

use crate::alerts::AlertLogger;
use crate::config::Config;
use crate::detection::{Detection, DetectionSource};
use crate::engine::RuleManager;
use crate::monitors::MonitorEvent;
use crate::response::ResponseExecutor;
use crate::{EdrError, Result};

/// EDR Daemon
pub struct Daemon {
    /// Configuration
    config: Config,
    /// Rule manager
    rule_manager: Arc<RwLock<RuleManager>>,
    /// Alert logger
    alert_logger: Arc<AlertLogger>,
    /// Response executor
    response_executor: Arc<ResponseExecutor>,
    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,
    /// Running flag
    running: Arc<RwLock<bool>>,
}

impl Daemon {
    /// Create a new daemon
    pub fn new(config: Config) -> Result<Self> {
        // Create rule manager
        let mut rule_manager = RuleManager::new(config.rules.clone());
        rule_manager.initialize()?;

        // Create alert logger
        let alert_logger = AlertLogger::new(config.alerts.clone())?;

        // Create response executor
        let response_executor = ResponseExecutor::new(config.response.clone())?;

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel(16);

        Ok(Self {
            config,
            rule_manager: Arc::new(RwLock::new(rule_manager)),
            alert_logger: Arc::new(alert_logger),
            response_executor: Arc::new(response_executor),
            shutdown_tx,
            running: Arc::new(RwLock::new(false)),
        })
    }

    /// Start the daemon
    pub async fn start(&self) -> Result<()> {
        info!("Starting YARA-EDR daemon");

        *self.running.write() = true;

        // Write PID file
        self.write_pid_file()?;

        // Create channels for events and detections
        let (event_tx, event_rx) = mpsc::channel::<MonitorEvent>(1000);
        let (detection_tx, detection_rx) = mpsc::channel::<Detection>(100);

        // Start event processor
        let processor_handle = self.start_event_processor(event_rx, detection_tx.clone());

        // Start detection handler
        let detection_handle = self.start_detection_handler(detection_rx);

        // Start file monitor if enabled
        let file_monitor_handle = if self.config.file_monitor.enabled {
            Some(self.start_file_monitor(event_tx.clone()))
        } else {
            info!("File monitoring disabled");
            None
        };

        // Start process monitor if enabled
        let process_monitor_handle = if self.config.process_monitor.enabled {
            Some(self.start_process_monitor(event_tx.clone()))
        } else {
            info!("Process monitoring disabled");
            None
        };

        // Start rule reload task
        let rule_reload_handle = self.start_rule_reload_task();

        info!("YARA-EDR daemon started");

        // Wait for shutdown signal
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        shutdown_rx.recv().await.ok();

        info!("Shutdown signal received, stopping daemon...");

        // Wait for tasks to complete
        processor_handle.await.ok();
        detection_handle.await.ok();

        if let Some(handle) = file_monitor_handle {
            handle.await.ok();
        }

        if let Some(handle) = process_monitor_handle {
            handle.await.ok();
        }

        rule_reload_handle.await.ok();

        // Clean up
        self.remove_pid_file();
        *self.running.write() = false;

        info!("YARA-EDR daemon stopped");

        Ok(())
    }

    /// Start the event processor task
    fn start_event_processor(
        &self,
        mut event_rx: mpsc::Receiver<MonitorEvent>,
        detection_tx: mpsc::Sender<Detection>,
    ) -> tokio::task::JoinHandle<()> {
        let rule_manager = self.rule_manager.clone();
        let config = self.config.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            info!("Event processor started");

            loop {
                tokio::select! {
                    Some(event) = event_rx.recv() => {
                        let scanner = {
                            let manager = rule_manager.read();
                            manager.scanner()
                        };

                        // Process detection outside of lock scope to avoid holding lock across await
                        let detection_to_send: Option<Detection> = match event {
                            MonitorEvent::FileCreated(file_event) |
                            MonitorEvent::FileModified(file_event) => {
                                // Scan the file - lock is held only during scan
                                let scan_result = {
                                    let scanner_guard = scanner.read();
                                    scanner_guard.scan_file(&file_event.path)
                                };
                                match scan_result {
                                    Ok(result) => {
                                        if result.is_match {
                                            let source = DetectionSource::FileMonitor {
                                                event_type: "created/modified".to_string(),
                                            };
                                            Some(Detection::new(result, source))
                                        } else {
                                            None
                                        }
                                    }
                                    Err(e) => {
                                        tracing::debug!("Scan error for {:?}: {}", file_event.path, e);
                                        None
                                    }
                                }
                            }
                            MonitorEvent::ProcessStarted(proc_event) => {
                                // Scan process if memory scanning is enabled
                                if config.process_monitor.memory_scan {
                                    let scan_result = {
                                        let scanner_guard = scanner.read();
                                        scanner_guard.scan_process(proc_event.pid)
                                    };
                                    match scan_result {
                                        Ok(result) => {
                                            if result.is_match {
                                                let source = DetectionSource::ProcessMonitor {
                                                    event_type: "started".to_string(),
                                                };
                                                Some(Detection::new(result, source))
                                            } else {
                                                None
                                            }
                                        }
                                        Err(e) => {
                                            tracing::debug!("Scan error for PID {}: {}", proc_event.pid, e);
                                            None
                                        }
                                    }
                                } else {
                                    None
                                }
                            }
                            _ => None
                        };

                        // Send detection after lock is released
                        if let Some(detection) = detection_to_send
                            && let Err(e) = detection_tx.send(detection).await {
                                error!("Failed to send detection: {}", e);
                            }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Event processor shutting down");
                        break;
                    }
                }
            }
        })
    }

    /// Start the detection handler task
    fn start_detection_handler(
        &self,
        mut detection_rx: mpsc::Receiver<Detection>,
    ) -> tokio::task::JoinHandle<()> {
        let alert_logger = self.alert_logger.clone();
        let response_executor = self.response_executor.clone();
        let _config = self.config.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            info!("Detection handler started");

            loop {
                tokio::select! {
                    Some(detection) = detection_rx.recv() => {
                        // Log the detection
                        if let Err(e) = alert_logger.log_detection(&detection) {
                            error!("Failed to log detection: {}", e);
                        }

                        // Execute automatic responses
                        let results = response_executor.execute_automatic(&detection);
                        for result in results {
                            if result.success {
                                info!("Response action executed: {:?}", result.action);
                            } else {
                                warn!("Response action failed: {:?} - {:?}", result.action, result.error);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Detection handler shutting down");
                        break;
                    }
                }
            }
        })
    }

    /// Start the file monitor task
    fn start_file_monitor(
        &self,
        event_tx: mpsc::Sender<MonitorEvent>,
    ) -> tokio::task::JoinHandle<()> {
        let config = self.config.file_monitor.clone();
        let shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            if let Err(e) =
                crate::monitors::file_monitor::start_file_monitor(config, event_tx, shutdown_rx)
                    .await
            {
                error!("File monitor error: {}", e);
            }
        })
    }

    /// Start the process monitor task
    fn start_process_monitor(
        &self,
        event_tx: mpsc::Sender<MonitorEvent>,
    ) -> tokio::task::JoinHandle<()> {
        let config = self.config.process_monitor.clone();
        let shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            if let Err(e) = crate::monitors::process_monitor::start_process_monitor(
                config,
                event_tx,
                shutdown_rx,
            )
            .await
            {
                error!("Process monitor error: {}", e);
            }
        })
    }

    /// Start the rule reload task
    fn start_rule_reload_task(&self) -> tokio::task::JoinHandle<()> {
        let rule_manager = self.rule_manager.clone();
        let interval = std::time::Duration::from_secs(self.config.rules.reload_interval);
        let shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            crate::engine::rules::start_reload_task(rule_manager, interval, shutdown_rx).await;
        })
    }

    /// Write PID file
    fn write_pid_file(&self) -> Result<()> {
        let pid = std::process::id();

        // Create parent directory if needed
        if let Some(parent) = self.config.general.pid_file.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&self.config.general.pid_file, pid.to_string())?;
        info!("PID file written: {:?}", self.config.general.pid_file);

        Ok(())
    }

    /// Remove PID file
    fn remove_pid_file(&self) {
        if self.config.general.pid_file.exists()
            && let Err(e) = fs::remove_file(&self.config.general.pid_file)
        {
            warn!("Failed to remove PID file: {}", e);
        }
    }

    /// Stop the daemon
    pub fn stop(&self) {
        info!("Stopping daemon...");
        let _ = self.shutdown_tx.send(());
    }

    /// Check if daemon is running
    pub fn is_running(&self) -> bool {
        *self.running.read()
    }

    /// Get daemon status
    pub fn status(&self) -> DaemonStatus {
        let rule_manager = self.rule_manager.read();
        let stats = rule_manager.stats();

        DaemonStatus {
            running: *self.running.read(),
            pid: std::process::id(),
            rules_loaded: stats.rules_loaded,
            rule_files: stats.file_count,
            config_path: self
                .config
                .general
                .log_file
                .parent()
                .map(std::path::Path::to_path_buf),
        }
    }
}

/// Daemon status information
#[derive(Debug)]
pub struct DaemonStatus {
    pub running: bool,
    pub pid: u32,
    pub rules_loaded: bool,
    pub rule_files: usize,
    pub config_path: Option<std::path::PathBuf>,
}

impl std::fmt::Display for DaemonStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "YARA-EDR Daemon Status")?;
        writeln!(f, "  Running: {}", self.running)?;
        writeln!(f, "  PID: {}", self.pid)?;
        writeln!(f, "  Rules loaded: {}", self.rules_loaded)?;
        writeln!(f, "  Rule files: {}", self.rule_files)?;
        if let Some(path) = &self.config_path {
            writeln!(f, "  Config dir: {path:?}")?;
        }
        Ok(())
    }
}

/// Check if daemon is already running by checking PID file
pub fn is_daemon_running<P: AsRef<Path>>(pid_file: P) -> bool {
    let pid_file = pid_file.as_ref();

    if !pid_file.exists() {
        return false;
    }

    // Read PID from file
    if let Ok(content) = fs::read_to_string(pid_file)
        && let Ok(pid) = content.trim().parse::<i32>()
    {
        // Check if process is running
        return crate::utils::process::is_process_running(pid);
    }

    false
}

/// Stop a running daemon by sending SIGTERM
pub fn stop_daemon<P: AsRef<Path>>(pid_file: P) -> Result<()> {
    let pid_file = pid_file.as_ref();

    if !pid_file.exists() {
        return Err(EdrError::Daemon("PID file not found".to_string()));
    }

    let content = fs::read_to_string(pid_file)?;
    let pid: i32 = content
        .trim()
        .parse()
        .map_err(|_| EdrError::Daemon("Invalid PID in file".to_string()))?;

    // Send SIGTERM
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGTERM,
    )
    .map_err(|e| EdrError::Daemon(format!("Failed to send SIGTERM: {e}")))?;

    info!("Sent SIGTERM to PID {}", pid);

    Ok(())
}

/// Daemonize the current process
pub fn daemonize() -> Result<()> {
    use daemonize::Daemonize;

    let daemonize = Daemonize::new().working_directory("/").umask(0o027);

    daemonize
        .start()
        .map_err(|e| EdrError::Daemon(format!("Failed to daemonize: {e}")))?;

    Ok(())
}
