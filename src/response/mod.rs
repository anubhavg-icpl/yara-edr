//! Response Module
//!
//! Provides response actions for detected threats.

pub mod actions;
pub mod quarantine;

pub use actions::{ResponseAction, ResponseExecutor};
pub use quarantine::QuarantineManager;
