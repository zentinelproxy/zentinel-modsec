//! # sentinel-modsec
//!
//! Pure Rust implementation of ModSecurity with full OWASP CRS compatibility.
//!
//! This crate provides a complete ModSecurity rule engine without any C/C++ dependencies,
//! making it easier to deploy, audit, and maintain.
//!
//! ## Features
//!
//! - Full SecRule language support
//! - OWASP CRS compatibility (800+ rules)
//! - Pure Rust libinjection for @detectSQLi/@detectXSS
//! - Thread-safe, async-ready transaction processing
//! - Zero external C/C++ dependencies
//!
//! ## Quick Start
//!
//! ```ignore
//! use sentinel_modsec::{ModSecurity, Rules, Transaction};
//!
//! // Create engine and load rules
//! let modsec = ModSecurity::new();
//! let mut rules = Rules::new();
//! rules.add_plain("SecRuleEngine On")?;
//! rules.add_file("/etc/modsecurity/crs/rules/*.conf")?;
//!
//! // Process a request
//! let mut tx = modsec.transaction(&rules);
//! tx.process_uri("/api/users?id=1", "GET", "HTTP/1.1")?;
//! tx.add_request_header("Host", "example.com")?;
//! tx.process_request_headers()?;
//!
//! // Check for intervention
//! if let Some(intervention) = tx.intervention() {
//!     println!("Blocked: status={}", intervention.status());
//! }
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]
#![deny(unsafe_code)]

pub mod error;
pub mod parser;
pub mod variables;
pub mod operators;
pub mod transformations;
pub mod actions;
pub mod engine;
pub mod libinjection;

// Re-export main types at crate root
pub use engine::{ModSecurity, Transaction, Intervention};
pub use engine::ruleset::{Rules, CompiledRuleset};
pub use error::{Error, Result};

/// Protocol version for compatibility tracking
pub const PROTOCOL_VERSION: u32 = 1;

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
