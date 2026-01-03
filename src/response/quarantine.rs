//! Quarantine Management
//!
//! Provides secure file quarantine functionality.

use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{EdrError, Result};

/// Quarantine entry metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Unique identifier
    pub id: Uuid,
    /// Original file path
    pub original_path: PathBuf,
    /// Path in quarantine
    pub quarantine_path: PathBuf,
    /// Original file name
    pub original_name: String,
    /// File size
    pub size: u64,
    /// MD5 hash
    pub md5: String,
    /// SHA256 hash
    pub sha256: String,
    /// Quarantine timestamp
    pub quarantined_at: chrono::DateTime<chrono::Utc>,
    /// Detection rule that triggered quarantine
    pub detection_rule: Option<String>,
    /// Original file permissions
    pub original_permissions: u32,
    /// Original file owner (UID)
    pub original_uid: u32,
    /// Original file group (GID)
    pub original_gid: u32,
}

/// Quarantine manager
pub struct QuarantineManager {
    /// Quarantine directory path
    quarantine_dir: PathBuf,
    /// Metadata file path
    metadata_file: PathBuf,
    /// Entries cache
    entries: Vec<QuarantineEntry>,
}

impl QuarantineManager {
    /// Create a new quarantine manager
    pub fn new<P: AsRef<Path>>(quarantine_dir: P) -> Result<Self> {
        let quarantine_dir = quarantine_dir.as_ref().to_path_buf();

        // Create quarantine directory with restricted permissions
        fs::create_dir_all(&quarantine_dir)?;

        // Set directory permissions to 700 (owner only)
        let mut perms = fs::metadata(&quarantine_dir)?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&quarantine_dir, perms)?;

        let metadata_file = quarantine_dir.join("metadata.json");

        let mut manager = Self {
            quarantine_dir,
            metadata_file,
            entries: Vec::new(),
        };

        // Load existing entries
        manager.load_metadata()?;

        Ok(manager)
    }

    /// Load quarantine metadata from disk
    fn load_metadata(&mut self) -> Result<()> {
        if self.metadata_file.exists() {
            let content = fs::read_to_string(&self.metadata_file)?;
            self.entries = serde_json::from_str(&content).unwrap_or_default();
            debug!("Loaded {} quarantine entries", self.entries.len());
        }

        Ok(())
    }

    /// Save quarantine metadata to disk
    fn save_metadata(&self) -> Result<()> {
        let content = serde_json::to_string_pretty(&self.entries)
            .map_err(|e| EdrError::Response(format!("Failed to serialize metadata: {e}")))?;

        fs::write(&self.metadata_file, content)?;
        debug!("Saved {} quarantine entries", self.entries.len());

        Ok(())
    }

    /// Quarantine a file
    pub fn quarantine_file<P: AsRef<Path>>(&mut self, path: P) -> Result<QuarantineEntry> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(EdrError::Response(format!("File not found: {path:?}")));
        }

        // Get file metadata
        let metadata = fs::metadata(path)?;

        // Read file for hashing
        let content = fs::read(path)?;

        // Calculate hashes
        let md5 = format!("{:x}", md5::compute(&content));
        let sha256 = crate::utils::hash::sha256_bytes(&content);

        // Generate unique ID and quarantine path
        let id = Uuid::new_v4();
        let quarantine_path = self.quarantine_dir.join(format!("{id}.quarantine"));

        // Get original permissions and ownership
        use std::os::unix::fs::MetadataExt;
        let original_permissions = metadata.mode();
        let original_uid = metadata.uid();
        let original_gid = metadata.gid();

        // Create quarantine entry
        let entry = QuarantineEntry {
            id,
            original_path: path.to_path_buf(),
            quarantine_path: quarantine_path.clone(),
            original_name: path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            size: metadata.len(),
            md5,
            sha256,
            quarantined_at: chrono::Utc::now(),
            detection_rule: None,
            original_permissions,
            original_uid,
            original_gid,
        };

        // Move file to quarantine
        fs::rename(path, &quarantine_path)?;

        // Remove executable permissions from quarantined file
        let mut perms = fs::metadata(&quarantine_path)?.permissions();
        perms.set_mode(0o600); // Read/write for owner only, no execute
        fs::set_permissions(&quarantine_path, perms)?;

        info!(
            "File quarantined: {:?} -> {:?} (ID: {})",
            path, quarantine_path, id
        );

        // Add to entries and save
        self.entries.push(entry.clone());
        self.save_metadata()?;

        Ok(entry)
    }

    /// Quarantine a file with detection info
    pub fn quarantine_file_with_rule<P: AsRef<Path>>(
        &mut self,
        path: P,
        rule_name: &str,
    ) -> Result<QuarantineEntry> {
        let mut entry = self.quarantine_file(path)?;
        entry.detection_rule = Some(rule_name.to_string());

        // Update in entries
        if let Some(existing) = self.entries.iter_mut().find(|e| e.id == entry.id) {
            existing.detection_rule.clone_from(&entry.detection_rule);
        }

        self.save_metadata()?;

        Ok(entry)
    }

    /// Restore a quarantined file
    pub fn restore(&mut self, id: Uuid) -> Result<PathBuf> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or_else(|| EdrError::Response(format!("Quarantine entry not found: {id}")))?;

        // Check if quarantine file exists
        if !entry.quarantine_path.exists() {
            return Err(EdrError::Response(format!(
                "Quarantine file not found: {:?}",
                entry.quarantine_path
            )));
        }

        // Check if original path is available
        if entry.original_path.exists() {
            return Err(EdrError::Response(format!(
                "Original path already exists: {:?}",
                entry.original_path
            )));
        }

        // Move file back to original location
        fs::rename(&entry.quarantine_path, &entry.original_path)?;

        // Restore original permissions
        let mut perms = fs::metadata(&entry.original_path)?.permissions();
        perms.set_mode(entry.original_permissions);
        fs::set_permissions(&entry.original_path, perms)?;

        // Restore ownership (requires root)
        if let Err(e) = nix::unistd::chown(
            &entry.original_path,
            Some(nix::unistd::Uid::from_raw(entry.original_uid)),
            Some(nix::unistd::Gid::from_raw(entry.original_gid)),
        ) {
            warn!("Failed to restore ownership: {}", e);
        }

        info!(
            "File restored: {:?} -> {:?}",
            entry.quarantine_path, entry.original_path
        );

        // Remove from entries
        self.entries.retain(|e| e.id != id);
        self.save_metadata()?;

        Ok(entry.original_path)
    }

    /// Delete a quarantined file permanently
    pub fn delete(&mut self, id: Uuid) -> Result<()> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or_else(|| EdrError::Response(format!("Quarantine entry not found: {id}")))?;

        // Delete the quarantined file
        if entry.quarantine_path.exists() {
            fs::remove_file(&entry.quarantine_path)?;
        }

        info!(
            "Quarantined file deleted: {} ({:?})",
            id, entry.original_path
        );

        // Remove from entries
        self.entries.retain(|e| e.id != id);
        self.save_metadata()?;

        Ok(())
    }

    /// Get all quarantine entries
    pub fn list(&self) -> &[QuarantineEntry] {
        &self.entries
    }

    /// Get a specific quarantine entry
    pub fn get(&self, id: Uuid) -> Option<&QuarantineEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Get quarantine entry by original path
    pub fn get_by_path<P: AsRef<Path>>(&self, path: P) -> Option<&QuarantineEntry> {
        let path = path.as_ref();
        self.entries.iter().find(|e| e.original_path == path)
    }

    /// Get total size of quarantined files
    pub fn total_size(&self) -> u64 {
        self.entries.iter().map(|e| e.size).sum()
    }

    /// Get count of quarantined files
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Clean old quarantine entries
    pub fn clean_old(&mut self, max_age_days: u32) -> Result<usize> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(i64::from(max_age_days));
        let mut removed = 0;

        let old_entries: Vec<Uuid> = self
            .entries
            .iter()
            .filter(|e| e.quarantined_at < cutoff)
            .map(|e| e.id)
            .collect();

        for id in old_entries {
            if let Err(e) = self.delete(id) {
                error!("Failed to delete old quarantine entry {}: {}", id, e);
            } else {
                removed += 1;
            }
        }

        info!("Cleaned {} old quarantine entries", removed);
        Ok(removed)
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
    use tempfile::TempDir;

    #[test]
    fn test_quarantine_manager() {
        let temp_dir = TempDir::new().unwrap();
        let quarantine_dir = temp_dir.path().join("quarantine");

        let mut manager = QuarantineManager::new(&quarantine_dir).unwrap();

        // Create a test file
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "test content").unwrap();

        // Quarantine the file
        let entry = manager.quarantine_file(&test_file).unwrap();

        assert!(!test_file.exists());
        assert!(entry.quarantine_path.exists());
        assert_eq!(manager.count(), 1);

        // Restore the file
        manager.restore(entry.id).unwrap();

        assert!(test_file.exists());
        assert!(!entry.quarantine_path.exists());
        assert_eq!(manager.count(), 0);
    }
}
