//! YARA Rules Management
//!
//! Handles loading, reloading, and managing YARA rules.

use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{debug, error, info};

use crate::config::RulesConfig;
use crate::{EdrError, Result};

use super::Scanner;

/// Manages YARA rules with hot-reload capability
pub struct RuleManager {
    /// Scanner instance
    scanner: Arc<RwLock<Scanner>>,
    /// Configuration
    config: RulesConfig,
    /// Last modification times for rule files
    file_mtimes: Arc<RwLock<HashMap<PathBuf, SystemTime>>>,
    /// Whether auto-reload is enabled
    auto_reload: bool,
    /// File watcher handle
    watcher: Option<RecommendedWatcher>,
}

impl RuleManager {
    /// Create a new rule manager
    pub fn new(config: RulesConfig) -> Self {
        let scanner = Scanner::new(config.clone());

        Self {
            scanner: Arc::new(RwLock::new(scanner)),
            config,
            file_mtimes: Arc::new(RwLock::new(HashMap::new())),
            auto_reload: true,
            watcher: None,
        }
    }

    /// Initialize the rule manager and load rules
    pub fn initialize(&mut self) -> Result<()> {
        info!("Initializing rule manager");

        // Initialize scanner
        {
            let mut scanner = self.scanner.write();
            scanner.initialize()?;
            scanner.load_rules()?;
        }

        // Record file modification times
        self.update_file_mtimes()?;

        // Setup file watcher if auto-reload is enabled
        if self.config.auto_reload {
            self.setup_watcher()?;
        }

        Ok(())
    }

    /// Get a reference to the scanner
    pub fn scanner(&self) -> Arc<RwLock<Scanner>> {
        self.scanner.clone()
    }

    /// Update recorded file modification times
    fn update_file_mtimes(&self) -> Result<()> {
        let mut mtimes = self.file_mtimes.write();
        mtimes.clear();

        for rules_path in &self.config.paths {
            if rules_path.exists() {
                self.collect_file_mtimes(&mut mtimes, rules_path)?;
            }
        }

        debug!("Tracking {} rule files for changes", mtimes.len());
        Ok(())
    }

    /// Recursively collect file modification times
    fn collect_file_mtimes(
        &self,
        mtimes: &mut HashMap<PathBuf, SystemTime>,
        path: &Path,
    ) -> Result<()> {
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "yar" || ext == "yara" {
                    if let Ok(metadata) = std::fs::metadata(path) {
                        if let Ok(mtime) = metadata.modified() {
                            mtimes.insert(path.to_path_buf(), mtime);
                        }
                    }
                }
            }
        } else if path.is_dir() {
            for entry in std::fs::read_dir(path)?.flatten() {
                self.collect_file_mtimes(mtimes, &entry.path())?;
            }
        }

        Ok(())
    }

    /// Setup file watcher for auto-reload
    fn setup_watcher(&mut self) -> Result<()> {
        let scanner = self.scanner.clone();
        let _file_mtimes = self.file_mtimes.clone();
        let _paths = self.config.paths.clone();

        let mut watcher = notify::recommended_watcher(
            move |result: std::result::Result<Event, notify::Error>| {
                match result {
                    Ok(event) => {
                        // Check if any YARA files changed
                        let yara_changed = event.paths.iter().any(|p| {
                            p.extension()
                                .map(|e| e == "yar" || e == "yara")
                                .unwrap_or(false)
                        });

                        if yara_changed {
                            info!("YARA rules changed, reloading...");

                            let scanner = scanner.write();
                            if let Err(e) = scanner.reload_rules() {
                                error!("Failed to reload rules: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("File watcher error: {}", e);
                    }
                }
            },
        )
        .map_err(|e| EdrError::Config(format!("Failed to create file watcher: {}", e)))?;

        // Watch all rule directories
        for path in &self.config.paths {
            if path.exists() && path.is_dir() {
                watcher.watch(path, RecursiveMode::Recursive).map_err(|e| {
                    EdrError::Config(format!("Failed to watch path {:?}: {}", path, e))
                })?;
                debug!("Watching {:?} for rule changes", path);
            }
        }

        self.watcher = Some(watcher);
        info!("Rule auto-reload enabled");

        Ok(())
    }

    /// Check for rule file changes and reload if necessary
    pub fn check_and_reload(&self) -> Result<bool> {
        let current_mtimes = self.file_mtimes.read();
        let mut needs_reload = false;

        for rules_path in &self.config.paths {
            if rules_path.exists() {
                needs_reload = self.check_path_changed(&current_mtimes, rules_path);
                if needs_reload {
                    break;
                }
            }
        }

        drop(current_mtimes);

        if needs_reload {
            self.reload()?;
            self.update_file_mtimes()?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Check if a path has changed
    fn check_path_changed(
        &self,
        current_mtimes: &HashMap<PathBuf, SystemTime>,
        path: &Path,
    ) -> bool {
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "yar" || ext == "yara" {
                    if let Ok(metadata) = std::fs::metadata(path) {
                        if let Ok(mtime) = metadata.modified() {
                            return current_mtimes.get(path) != Some(&mtime);
                        }
                    }
                }
            }
        } else if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    if self.check_path_changed(current_mtimes, &entry.path()) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Reload rules
    pub fn reload(&self) -> Result<()> {
        info!("Reloading YARA rules");

        let scanner = self.scanner.write();
        scanner.reload_rules()?;

        info!("YARA rules reloaded successfully");
        Ok(())
    }

    /// Disable auto-reload
    pub fn disable_auto_reload(&mut self) {
        self.auto_reload = false;
        self.watcher = None;
        info!("Rule auto-reload disabled");
    }

    /// Enable auto-reload
    pub fn enable_auto_reload(&mut self) -> Result<()> {
        self.auto_reload = true;
        self.setup_watcher()?;
        Ok(())
    }

    /// Get list of loaded rule files
    pub fn get_rule_files(&self) -> Vec<PathBuf> {
        self.file_mtimes.read().keys().cloned().collect()
    }

    /// Get rule statistics
    pub fn stats(&self) -> RuleStats {
        let scanner = self.scanner.read();
        let file_count = self.file_mtimes.read().len();

        RuleStats {
            file_count,
            rules_loaded: scanner.has_rules(),
            auto_reload: self.auto_reload,
            paths: self.config.paths.clone(),
        }
    }
}

/// Rule manager statistics
#[derive(Debug, Clone)]
pub struct RuleStats {
    pub file_count: usize,
    pub rules_loaded: bool,
    pub auto_reload: bool,
    pub paths: Vec<PathBuf>,
}

impl std::fmt::Display for RuleStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Rule Statistics:")?;
        writeln!(f, "  Files loaded: {}", self.file_count)?;
        writeln!(f, "  Rules loaded: {}", self.rules_loaded)?;
        writeln!(f, "  Auto-reload: {}", self.auto_reload)?;
        writeln!(f, "  Rule paths:")?;
        for path in &self.paths {
            writeln!(f, "    - {:?}", path)?;
        }
        Ok(())
    }
}

/// Start a background rule reload task
pub async fn start_reload_task(
    rule_manager: Arc<RwLock<RuleManager>>,
    interval: Duration,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    info!("Starting rule reload task with interval: {:?}", interval);

    let mut interval_timer = tokio::time::interval(interval);

    loop {
        tokio::select! {
            _ = interval_timer.tick() => {
                let manager = rule_manager.read();
                match manager.check_and_reload() {
                    Ok(reloaded) => {
                        if reloaded {
                            info!("Rules reloaded via periodic check");
                        }
                    }
                    Err(e) => {
                        error!("Failed to check/reload rules: {}", e);
                    }
                }
            }
            _ = shutdown.recv() => {
                info!("Rule reload task shutting down");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_stats_display() {
        let stats = RuleStats {
            file_count: 5,
            rules_loaded: true,
            auto_reload: true,
            paths: vec![PathBuf::from("/etc/yara-edr/rules")],
        };

        let display = format!("{}", stats);
        assert!(display.contains("Files loaded: 5"));
        assert!(display.contains("Rules loaded: true"));
    }
}
