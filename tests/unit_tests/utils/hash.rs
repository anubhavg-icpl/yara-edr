//! Unit tests for hash utilities.

use yara_edr::utils::{md5_bytes, sha256_bytes};

#[test]
fn test_sha256_bytes() {
    let hash = sha256_bytes(b"hello world");
    assert_eq!(
        hash,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
}

#[test]
fn test_md5_bytes() {
    let hash = md5_bytes(b"hello world");
    assert_eq!(hash, "5eb63bbbe01eeed093cb22bb8f5acdc3");
}

#[test]
fn test_sha256_empty() {
    let hash = sha256_bytes(b"");
    assert_eq!(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_md5_empty() {
    let hash = md5_bytes(b"");
    assert_eq!(hash, "d41d8cd98f00b204e9800998ecf8427e");
}

#[test]
fn test_hash_consistency() {
    // Same input should always produce same output
    let input = b"test data for hashing";
    let hash1 = sha256_bytes(input);
    let hash2 = sha256_bytes(input);
    assert_eq!(hash1, hash2);
}
