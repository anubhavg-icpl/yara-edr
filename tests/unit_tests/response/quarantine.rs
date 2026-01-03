//! Unit tests for quarantine manager.

use std::fs;
use tempfile::TempDir;
use yara_edr::response::QuarantineManager;

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

#[test]
fn test_quarantine_preserves_content() {
    let temp_dir = TempDir::new().unwrap();
    let quarantine_dir = temp_dir.path().join("quarantine");

    let mut manager = QuarantineManager::new(&quarantine_dir).unwrap();

    // Create a test file with specific content
    let test_file = temp_dir.path().join("test_content.txt");
    let content = "This is test content that should be preserved";
    fs::write(&test_file, content).unwrap();

    // Quarantine and restore
    let entry = manager.quarantine_file(&test_file).unwrap();
    manager.restore(entry.id).unwrap();

    // Verify content is preserved
    let restored_content = fs::read_to_string(&test_file).unwrap();
    assert_eq!(restored_content, content);
}

#[test]
fn test_quarantine_list() {
    let temp_dir = TempDir::new().unwrap();
    let quarantine_dir = temp_dir.path().join("quarantine");

    let mut manager = QuarantineManager::new(&quarantine_dir).unwrap();

    // Create and quarantine multiple files
    for i in 0..3 {
        let test_file = temp_dir.path().join(format!("test_{i}.txt"));
        fs::write(&test_file, format!("content {i}")).unwrap();
        manager.quarantine_file(&test_file).unwrap();
    }

    assert_eq!(manager.count(), 3);

    let entries = manager.list();
    assert_eq!(entries.len(), 3);
}
