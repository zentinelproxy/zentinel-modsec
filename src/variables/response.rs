//! Response data for variable resolution.

use super::collection::HashMapCollection;

/// Response data container.
#[derive(Debug, Clone, Default)]
pub struct ResponseData {
    /// HTTP status code.
    pub status: u16,
    /// Response protocol.
    pub protocol: String,
    /// Response headers.
    pub headers: HashMapCollection,
    /// Response body.
    pub body: Vec<u8>,
    /// Content type.
    pub content_type: String,
}

impl ResponseData {
    /// Create new response data.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the status code.
    pub fn set_status(&mut self, status: u16) {
        self.status = status;
    }

    /// Set the protocol.
    pub fn set_protocol(&mut self, protocol: &str) {
        self.protocol = protocol.to_string();
    }

    /// Add a response header.
    pub fn add_header(&mut self, name: &str, value: &str) {
        self.headers.add(name.to_lowercase(), value.to_string());

        // Track content-type
        if name.eq_ignore_ascii_case("content-type") {
            self.content_type = value.to_string();
        }
    }

    /// Append to response body.
    pub fn append_body(&mut self, data: &[u8]) {
        self.body.extend_from_slice(data);
    }

    /// Get body as string.
    pub fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// Get body length.
    pub fn body_length(&self) -> usize {
        self.body.len()
    }
}
