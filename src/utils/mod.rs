//! Utilities Module
//!
//! Common utility functions used across the EDR agent.

pub mod hash;
pub mod process;

// Re-export commonly used items
pub use hash::{FileHashes, md5_bytes, md5_file, sha256_bytes, sha256_file};
pub use process::{
    MemoryRegion, get_process_cmdline, get_process_exe, is_process_running, parse_maps_line,
};
