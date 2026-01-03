//! YARA Engine Module
//!
//! This module provides the core YARA scanning functionality,
//! including rule loading, compilation, and scanning operations.

pub mod rules;
pub mod scanner;

pub use rules::{RuleManager, RuleStats};
pub use scanner::{ScanResult, ScanType, Scanner, YaraMatch};
