// UCOP-X Enterprise - Microkernel Core Library
// This crate implements the foundational microkernel with capability-based
// security, event bus, module lifecycle, and zero-trust architecture.

#![forbid(unsafe_code)]
#![deny(missing_docs, missing_debug_implementations, unreachable_pub)]
#![warn(clippy::all, clippy::pedantic, clippy::cargo)]

// Re-export core types at crate root
pub use capability::*;
pub use error::*;
pub use event::*;
pub use kernel::*;
pub use module::*;
pub use types::*;

pub mod capability;
pub mod error;
pub mod event;
pub mod kernel;
pub mod module;
pub mod types;
