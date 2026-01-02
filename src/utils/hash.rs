//! Hash Utilities
//!
//! Provides hashing functions for files and data.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::Result;

/// Calculate SHA256 hash of a file
pub fn sha256_file<P: AsRef<Path>>(path: P) -> Result<String> {
    let file = File::open(path.as_ref())?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Calculate SHA256 hash of bytes
pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Calculate MD5 hash of a file
pub fn md5_file<P: AsRef<Path>>(path: P) -> Result<String> {
    use md5::{Digest as Md5Digest, Md5};

    let file = File::open(path.as_ref())?;
    let mut reader = BufReader::new(file);
    let mut hasher = Md5::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Calculate MD5 hash of bytes
pub fn md5_bytes(data: &[u8]) -> String {
    use md5::{Digest as Md5Digest, Md5};

    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Hash information for a file
#[derive(Debug, Clone)]
pub struct FileHashes {
    pub md5: String,
    pub sha256: String,
}

/// Calculate all hashes for a file
pub fn hash_file<P: AsRef<Path>>(path: P) -> Result<FileHashes> {
    let path = path.as_ref();

    Ok(FileHashes {
        md5: md5_file(path)?,
        sha256: sha256_file(path)?,
    })
}

/// Calculate all hashes for bytes
pub fn hash_bytes(data: &[u8]) -> FileHashes {
    FileHashes {
        md5: md5_bytes(data),
        sha256: sha256_bytes(data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
