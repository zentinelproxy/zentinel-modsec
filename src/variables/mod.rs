//! Variable system for ModSecurity.
//!
//! This module handles variable resolution and collection management.

mod collection;
mod request;
mod response;
mod tx;
mod resolver;

pub use collection::{Collection, MutableCollection, HashMapCollection};
pub use request::RequestData;
pub use response::ResponseData;
pub use tx::TxCollection;
pub use resolver::VariableResolver;
