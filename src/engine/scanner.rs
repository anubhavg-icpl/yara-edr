//! YARA Scanner Implementation
//!
//! Provides a high-level interface for YARA scanning operations.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, warn};
use yara::{Compiler, Rules};

use crate::config::RulesConfig;
use crate::{EdrError, Result};

/// Represents a single string match within a YARA rule match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringMatch {
    /// String identifier (e.g., "$s1")
    pub identifier: String,
    /// Offset where the match occurred
    pub offset: usize,
    /// Length of the match
    pub length: usize,
    /// Matched data (if available)
    pub data: Option<Vec<u8>>,
}

/// Represents a YARA rule match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    /// Rule identifier
    pub rule: String,
    /// Rule namespace
    pub namespace: String,
    /// Rule tags
    pub tags: Vec<String>,
    /// Rule metadata
    pub metadata: Vec<(String, String)>,
    /// Matched strings
    pub strings: Vec<StringMatch>,
}

/// Result of a YARA scan operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Path or identifier of the scanned target
    pub target: String,
    /// Type of scan (file, process, memory)
    pub scan_type: ScanType,
    /// List of matched rules
    pub matches: Vec<YaraMatch>,
    /// Scan duration
    pub duration_ms: u64,
    /// Timestamp of the scan
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Whether any rules matched
    pub is_match: bool,
    /// File/data size in bytes
    pub size: u64,
    /// Hash of the scanned data (if applicable)
    pub hashes: Option<Hashes>,
}

/// Type of scan performed
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanType {
    File,
    Process,
    Memory,
    Buffer,
}

/// File hashes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hashes {
    pub md5: String,
    pub sha256: String,
}

/// YARA Scanner wrapper
pub struct Scanner {
    /// Compiled YARA rules
    rules: Arc<RwLock<Option<Rules>>>,
    /// Configuration
    config: RulesConfig,
    /// Whether the scanner is initialized
    initialized: bool,
}

impl Scanner {
    /// Create a new scanner with the given configuration
    pub fn new(config: RulesConfig) -> Self {
        Self {
            rules: Arc::new(RwLock::new(None)),
            config,
            initialized: false,
        }
    }

    /// Initialize the YARA library
    pub fn initialize(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }

        debug!("Initializing YARA library");

        // YARA library is automatically initialized when creating Rules
        self.initialized = true;
        info!("YARA library initialized");

        Ok(())
    }

    /// Load and compile YARA rules from configured paths
    pub fn load_rules(&self) -> Result<()> {
        info!("Loading YARA rules from configured paths");

        let compiler = Compiler::new()
            .map_err(|e| EdrError::Yara(format!("Failed to create YARA compiler: {e}")))?;

        // Collect all rule files first
        let mut rule_files = Vec::new();
        for rules_path in &self.config.paths {
            if !rules_path.exists() {
                warn!("Rules path does not exist: {:?}", rules_path);
                continue;
            }

            if rules_path.is_file() {
                rule_files.push(rules_path.clone());
            } else if rules_path.is_dir() {
                self.collect_rule_files(rules_path, &mut rule_files);
            }
        }

        if rule_files.is_empty() {
            warn!("No YARA rules were loaded");
            return Ok(());
        }

        // Load all rules using builder pattern
        let mut compiler = Some(compiler);
        let mut rules_loaded = 0;

        for path in &rule_files {
            let Some(current_compiler) = compiler.take() else {
                error!("Compiler lost due to previous error, stopping rule loading");
                break;
            };

            match std::fs::read_to_string(path) {
                Ok(content) => {
                    match current_compiler.add_rules_str(&content) {
                        Ok(new_compiler) => {
                            compiler = Some(new_compiler);
                            rules_loaded += 1;
                            debug!("Loaded rule file: {:?}", path);
                        },
                        Err(e) => {
                            error!("Failed to add rules from {:?}: {}", path, e);
                            // Compiler is lost on error, need to recreate
                            compiler = Compiler::new().ok();
                        },
                    }
                },
                Err(e) => {
                    error!("Failed to read rule file {:?}: {}", path, e);
                    // Put the compiler back since we didn't use it
                    compiler = Some(current_compiler);
                },
            }
        }

        info!("Loaded {} YARA rule file(s)", rules_loaded);

        let compiler = compiler
            .ok_or_else(|| EdrError::Yara("Compiler was lost during rule loading".to_string()))?;

        let rules = compiler
            .compile_rules()
            .map_err(|e| EdrError::Yara(format!("Failed to compile YARA rules: {e}")))?;

        let mut rules_guard = self.rules.write();
        *rules_guard = Some(rules);

        Ok(())
    }

    /// Collect rule files from a directory recursively
    fn collect_rule_files(&self, dir: &Path, files: &mut Vec<std::path::PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension()
                        && (ext == "yar" || ext == "yara")
                    {
                        files.push(path);
                    }
                } else if path.is_dir() {
                    self.collect_rule_files(&path, files);
                }
            }
        }
    }

    /// Scan a file
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<ScanResult> {
        let path = path.as_ref();
        let start = Instant::now();

        debug!("Scanning file: {:?}", path);

        let rules_guard = self.rules.read();
        let rules = rules_guard
            .as_ref()
            .ok_or_else(|| EdrError::Yara("YARA rules not loaded".to_string()))?;

        let file_size = std::fs::metadata(path)?.len();

        // Check file size limit
        if self.config.scan_timeout > 0 {
            // File size is checked by the caller if needed
        }

        let scan_results = rules
            .scan_file(path, self.config.scan_timeout as i32)
            .map_err(|e| EdrError::Yara(format!("Failed to scan file {path:?}: {e}")))?;

        let matches = self.convert_matches(&scan_results);
        let duration = start.elapsed();

        // Calculate hashes
        let hashes = self.calculate_file_hashes(path).ok();

        let result = ScanResult {
            target: path.to_string_lossy().to_string(),
            scan_type: ScanType::File,
            matches: matches.clone(),
            duration_ms: duration.as_millis() as u64,
            timestamp: chrono::Utc::now(),
            is_match: !matches.is_empty(),
            size: file_size,
            hashes,
        };

        if result.is_match {
            info!("File {:?} matched {} rule(s)", path, result.matches.len());
        }

        Ok(result)
    }

    /// Scan a memory buffer
    pub fn scan_buffer(&self, data: &[u8], identifier: &str) -> Result<ScanResult> {
        let start = Instant::now();

        debug!("Scanning buffer: {} ({} bytes)", identifier, data.len());

        let rules_guard = self.rules.read();
        let rules = rules_guard
            .as_ref()
            .ok_or_else(|| EdrError::Yara("YARA rules not loaded".to_string()))?;

        let scan_results = rules
            .scan_mem(data, self.config.scan_timeout as i32)
            .map_err(|e| EdrError::Yara(format!("Failed to scan buffer: {e}")))?;

        let matches = self.convert_matches(&scan_results);
        let duration = start.elapsed();

        // Calculate hashes
        let hashes = Some(Hashes {
            md5: format!("{:x}", md5::compute(data)),
            sha256: crate::utils::hash::sha256_bytes(data),
        });

        let result = ScanResult {
            target: identifier.to_string(),
            scan_type: ScanType::Buffer,
            matches: matches.clone(),
            duration_ms: duration.as_millis() as u64,
            timestamp: chrono::Utc::now(),
            is_match: !matches.is_empty(),
            size: data.len() as u64,
            hashes,
        };

        if result.is_match {
            info!(
                "Buffer {} matched {} rule(s)",
                identifier,
                result.matches.len()
            );
        }

        Ok(result)
    }

    /// Scan a process by PID
    pub fn scan_process(&self, pid: i32) -> Result<ScanResult> {
        let start = Instant::now();

        debug!("Scanning process: {}", pid);

        let rules_guard = self.rules.read();
        let rules = rules_guard
            .as_ref()
            .ok_or_else(|| EdrError::Yara("YARA rules not loaded".to_string()))?;

        // Read process memory regions
        let memory_data = crate::utils::process::read_process_memory(pid)?;

        let scan_results = rules
            .scan_mem(&memory_data, self.config.scan_timeout as i32)
            .map_err(|e| EdrError::Yara(format!("Failed to scan process {pid}: {e}")))?;

        let matches = self.convert_matches(&scan_results);
        let duration = start.elapsed();

        let result = ScanResult {
            target: format!("pid:{pid}"),
            scan_type: ScanType::Process,
            matches: matches.clone(),
            duration_ms: duration.as_millis() as u64,
            timestamp: chrono::Utc::now(),
            is_match: !matches.is_empty(),
            size: memory_data.len() as u64,
            hashes: None,
        };

        if result.is_match {
            info!("Process {} matched {} rule(s)", pid, result.matches.len());
        }

        Ok(result)
    }

    /// Convert YARA rule matches to our format
    fn convert_matches(&self, yara_rules: &[yara::Rule]) -> Vec<YaraMatch> {
        yara_rules
            .iter()
            .map(|rule| {
                let strings: Vec<StringMatch> = rule
                    .strings
                    .iter()
                    .flat_map(|s| {
                        s.matches.iter().map(|m| StringMatch {
                            identifier: s.identifier.to_string(),
                            offset: m.offset,
                            length: m.data.len(),
                            data: Some(m.data.clone()),
                        })
                    })
                    .collect();

                let metadata: Vec<(String, String)> = rule
                    .metadatas
                    .iter()
                    .map(|m| {
                        let value = match &m.value {
                            yara::MetadataValue::Integer(i) => i.to_string(),
                            yara::MetadataValue::String(s) => (*s).to_string(),
                            yara::MetadataValue::Boolean(b) => b.to_string(),
                        };
                        (m.identifier.to_string(), value)
                    })
                    .collect();

                YaraMatch {
                    rule: rule.identifier.to_string(),
                    namespace: rule.namespace.to_string(),
                    tags: rule.tags.iter().map(|t| (*t).to_string()).collect(),
                    metadata,
                    strings,
                }
            })
            .collect()
    }

    /// Calculate file hashes
    fn calculate_file_hashes(&self, path: &Path) -> Result<Hashes> {
        let data = std::fs::read(path)?;

        Ok(Hashes {
            md5: format!("{:x}", md5::compute(&data)),
            sha256: crate::utils::hash::sha256_bytes(&data),
        })
    }

    /// Reload YARA rules
    pub fn reload_rules(&self) -> Result<()> {
        info!("Reloading YARA rules");
        self.load_rules()
    }

    /// Check if rules are loaded
    pub fn has_rules(&self) -> bool {
        self.rules.read().is_some()
    }

    /// Get the number of loaded rules
    pub fn rule_count(&self) -> usize {
        // YARA rules don't expose a count directly, so we return 0 if loaded
        if self.has_rules() {
            1 // At least some rules are loaded
        } else {
            0
        }
    }
}

impl Drop for Scanner {
    fn drop(&mut self) {
        debug!("Dropping YARA scanner");
    }
}

// Use md5 crate
mod md5 {
    pub fn compute(data: &[u8]) -> Digest {
        use md5::Digest as Md5Digest;
        use md5::Md5;

        let mut hasher = Md5::new();
        hasher.update(data);
        Digest(hasher.finalize().into())
    }

    pub struct Digest([u8; 16]);

    impl std::fmt::LowerHex for Digest {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            for byte in &self.0 {
                write!(f, "{byte:02x}")?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_result_serialization() {
        let result = ScanResult {
            target: "/tmp/test".to_string(),
            scan_type: ScanType::File,
            matches: vec![],
            duration_ms: 100,
            timestamp: chrono::Utc::now(),
            is_match: false,
            size: 1024,
            hashes: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("/tmp/test"));
    }
}
