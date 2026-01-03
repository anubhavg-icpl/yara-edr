//! File System Monitor
//!
//! Monitors file system events using inotify on Linux.

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::FileMonitorConfig;
use crate::{EdrError, Result};

use super::{FileEvent, MonitorEvent};

/// File system monitor using inotify
pub struct FileMonitor {
    /// inotify instance
    inotify: Inotify,
    /// Configuration
    config: FileMonitorConfig,
    /// Watch descriptors mapped to paths
    watches: Arc<RwLock<HashMap<WatchDescriptor, PathBuf>>>,
    /// Reverse mapping: paths to watch descriptors
    path_watches: Arc<RwLock<HashMap<PathBuf, WatchDescriptor>>>,
    /// Event sender channel
    event_tx: Option<mpsc::Sender<MonitorEvent>>,
    /// Debounce tracking
    last_events: Arc<RwLock<HashMap<PathBuf, Instant>>>,
    /// Running flag
    running: Arc<RwLock<bool>>,
}

impl FileMonitor {
    /// Create a new file monitor
    pub fn new(config: FileMonitorConfig) -> Result<Self> {
        let inotify = Inotify::init()
            .map_err(|e| EdrError::FileMonitor(format!("Failed to initialize inotify: {e}")))?;

        Ok(Self {
            inotify,
            config,
            watches: Arc::new(RwLock::new(HashMap::new())),
            path_watches: Arc::new(RwLock::new(HashMap::new())),
            event_tx: None,
            last_events: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(false)),
        })
    }

    /// Set the event sender channel
    pub fn set_event_channel(&mut self, tx: mpsc::Sender<MonitorEvent>) {
        self.event_tx = Some(tx);
    }

    /// Initialize watches on configured paths
    pub fn initialize(&mut self) -> Result<()> {
        info!("Initializing file monitor");

        for watch_path in &self.config.watch_paths.clone() {
            if watch_path.exists() {
                self.add_watch(watch_path)?;
            } else {
                warn!("Watch path does not exist: {:?}", watch_path);
            }
        }

        let watch_count = self.watches.read().len();
        info!("File monitor initialized with {} watches", watch_count);

        Ok(())
    }

    /// Add a watch on a path
    pub fn add_watch<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(EdrError::FileMonitor(format!(
                "Path does not exist: {path:?}"
            )));
        }

        // Skip if already watching
        if self.path_watches.read().contains_key(path) {
            return Ok(());
        }

        let mask = WatchMask::CREATE
            | WatchMask::MODIFY
            | WatchMask::CLOSE_WRITE
            | WatchMask::DELETE
            | WatchMask::MOVED_FROM
            | WatchMask::MOVED_TO;

        let wd =
            self.inotify.watches().add(path, mask).map_err(|e| {
                EdrError::FileMonitor(format!("Failed to add watch on {path:?}: {e}"))
            })?;

        let path_buf = path.to_path_buf();
        self.watches.write().insert(wd.clone(), path_buf.clone());
        self.path_watches.write().insert(path_buf.clone(), wd);

        debug!("Added watch on {:?}", path);

        // Recursively watch subdirectories
        if self.config.recursive && path.is_dir() {
            self.watch_directory_recursive(path)?;
        }

        Ok(())
    }

    /// Recursively add watches on subdirectories
    fn watch_directory_recursive(&mut self, dir: &Path) -> Result<()> {
        let entries = std::fs::read_dir(dir)?;

        for entry in entries.flatten() {
            let path = entry.path();

            if path.is_dir() {
                // Check exclusion patterns
                if !self.is_excluded(&path) {
                    self.add_watch(&path)?;
                }
            }
        }

        Ok(())
    }

    /// Remove a watch on a path
    pub fn remove_watch<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();

        if let Some(wd) = self.path_watches.write().remove(path) {
            self.inotify.watches().remove(wd.clone()).ok();
            self.watches.write().remove(&wd);
            debug!("Removed watch on {:?}", path);
        }

        Ok(())
    }

    /// Check if a path matches exclusion patterns
    pub fn is_excluded(&self, path: &Path) -> bool {
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

    /// Check if a file should be scanned based on extension
    pub fn should_scan_file(&self, path: &Path) -> bool {
        // Check exclusion patterns first
        if self.is_excluded(path) {
            return false;
        }

        // Check file size
        if self.config.max_file_size > 0
            && let Ok(metadata) = std::fs::metadata(path)
            && metadata.len() > self.config.max_file_size
        {
            debug!("Skipping large file: {:?}", path);
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

    /// Check debounce for a path
    fn check_debounce(&self, path: &Path) -> bool {
        let debounce_duration = Duration::from_millis(self.config.debounce_ms);

        let mut last_events = self.last_events.write();

        if let Some(last_time) = last_events.get(path)
            && last_time.elapsed() < debounce_duration
        {
            return false; // Still within debounce period
        }

        last_events.insert(path.to_path_buf(), Instant::now());
        true
    }

    /// Start monitoring in a separate task
    pub async fn start(
        &mut self,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<()> {
        info!("Starting file monitor");

        *self.running.write() = true;

        let mut buffer = [0u8; 4096];

        loop {
            tokio::select! {
                _result = tokio::task::spawn_blocking({
                    let _inotify_fd = self.inotify.as_fd();
                    move || {
                        // This is a simplified version - in practice you'd use
                        // proper async inotify handling
                        std::thread::sleep(Duration::from_millis(100));
                        Ok::<_, std::io::Error>(())
                    }
                }) => {
                    // Read events
                    match self.inotify.read_events(&mut buffer) {
                        Ok(events) => {
                            for event in events {
                                self.handle_event(&event).await;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // No events available
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        Err(e) => {
                            error!("Error reading inotify events: {}", e);
                        }
                    }
                }
                _ = shutdown.recv() => {
                    info!("File monitor shutting down");
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

    /// Handle an inotify event
    async fn handle_event(&self, event: &inotify::Event<&std::ffi::OsStr>) {
        // Get the watched directory
        let watched_path = match self.watches.read().get(&event.wd) {
            Some(path) => path.clone(),
            None => return,
        };

        // Build full path
        let full_path = if let Some(name) = &event.name {
            watched_path.join(name)
        } else {
            watched_path
        };

        // Check if we should process this file
        if full_path.is_file() && !self.should_scan_file(&full_path) {
            return;
        }

        // Check debounce
        if !self.check_debounce(&full_path) {
            return;
        }

        let monitor_event = if event.mask.contains(EventMask::CREATE) {
            debug!("File created: {:?}", full_path);
            Some(MonitorEvent::FileCreated(FileEvent::new(full_path)))
        } else if event.mask.contains(EventMask::MODIFY)
            || event.mask.contains(EventMask::CLOSE_WRITE)
        {
            debug!("File modified: {:?}", full_path);
            Some(MonitorEvent::FileModified(FileEvent::new(full_path)))
        } else if event.mask.contains(EventMask::DELETE) {
            debug!("File deleted: {:?}", full_path);
            Some(MonitorEvent::FileDeleted(FileEvent::new(full_path)))
        } else if event.mask.contains(EventMask::ISDIR) && event.mask.contains(EventMask::CREATE) {
            // New directory created - add watch if recursive
            if self.config.recursive && !self.is_excluded(&full_path) {
                // Note: Can't mutably borrow self here, would need to handle differently
                debug!("New directory created: {:?}", full_path);
            }
            None
        } else {
            None
        };

        // Send event through channel
        if let (Some(event), Some(tx)) = (monitor_event, &self.event_tx)
            && let Err(e) = tx.send(event).await
        {
            error!("Failed to send file event: {}", e);
        }
    }

    /// Stop monitoring
    pub fn stop(&mut self) {
        info!("Stopping file monitor");
        *self.running.write() = false;
    }

    /// Check if monitor is running
    pub fn is_running(&self) -> bool {
        *self.running.read()
    }

    /// Get number of active watches
    pub fn watch_count(&self) -> usize {
        self.watches.read().len()
    }

    /// Get list of watched paths
    pub fn watched_paths(&self) -> Vec<PathBuf> {
        self.watches.read().values().cloned().collect()
    }
}

impl Drop for FileMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Start file monitoring task
pub async fn start_file_monitor(
    config: FileMonitorConfig,
    event_tx: mpsc::Sender<MonitorEvent>,
    shutdown: tokio::sync::broadcast::Receiver<()>,
) -> Result<()> {
    let mut monitor = FileMonitor::new(config)?;
    monitor.set_event_channel(event_tx);
    monitor.initialize()?;
    monitor.start(shutdown).await
}
