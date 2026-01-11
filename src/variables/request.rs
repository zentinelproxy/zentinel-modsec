//! Request data for variable resolution.

use super::collection::{Collection, HashMapCollection};

/// Request data container.
#[derive(Debug, Clone, Default)]
pub struct RequestData {
    /// HTTP method.
    pub method: String,
    /// Request URI (with query string).
    pub uri: String,
    /// Raw URI.
    pub uri_raw: String,
    /// Request path (without query string).
    pub path: String,
    /// Query string.
    pub query_string: String,
    /// HTTP protocol version.
    pub protocol: String,
    /// Request headers.
    pub headers: HashMapCollection,
    /// GET arguments.
    pub args_get: HashMapCollection,
    /// POST arguments.
    pub args_post: HashMapCollection,
    /// Cookies.
    pub cookies: HashMapCollection,
    /// Request body.
    pub body: Vec<u8>,
    /// Client IP address.
    pub client_ip: String,
    /// Client port.
    pub client_port: u16,
    /// Server name.
    pub server_name: String,
    /// Server port.
    pub server_port: u16,
}

impl RequestData {
    /// Create new request data.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the URI and parse path/query string.
    pub fn set_uri(&mut self, uri: &str) {
        self.uri = uri.to_string();
        self.uri_raw = uri.to_string();

        if let Some(pos) = uri.find('?') {
            self.path = uri[..pos].to_string();
            self.query_string = uri[pos + 1..].to_string();
            self.parse_query_string(&self.query_string.clone());
        } else {
            self.path = uri.to_string();
            self.query_string.clear();
        }
    }

    /// Set the HTTP method.
    pub fn set_method(&mut self, method: &str) {
        self.method = method.to_string();
    }

    /// Set the protocol.
    pub fn set_protocol(&mut self, protocol: &str) {
        self.protocol = protocol.to_string();
    }

    /// Add a request header.
    pub fn add_header(&mut self, name: &str, value: &str) {
        self.headers.add(name.to_lowercase(), value.to_string());
    }

    /// Append to request body.
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

    /// Parse query string into args_get.
    fn parse_query_string(&mut self, qs: &str) {
        for pair in qs.split('&') {
            if let Some(pos) = pair.find('=') {
                let key = &pair[..pos];
                let value = &pair[pos + 1..];
                // URL decode
                let key = percent_encoding::percent_decode_str(key)
                    .decode_utf8_lossy()
                    .to_string();
                let value = percent_encoding::percent_decode_str(value)
                    .decode_utf8_lossy()
                    .to_string();
                self.args_get.add(key, value);
            } else if !pair.is_empty() {
                let key = percent_encoding::percent_decode_str(pair)
                    .decode_utf8_lossy()
                    .to_string();
                self.args_get.add(key, String::new());
            }
        }
    }

    /// Parse form body into args_post.
    pub fn parse_form_body(&mut self) {
        let body_str = self.body_str();
        for pair in body_str.split('&') {
            if let Some(pos) = pair.find('=') {
                let key = &pair[..pos];
                let value = &pair[pos + 1..];
                let key = percent_encoding::percent_decode_str(key)
                    .decode_utf8_lossy()
                    .to_string();
                let value = percent_encoding::percent_decode_str(value)
                    .decode_utf8_lossy()
                    .to_string();
                self.args_post.add(key, value);
            }
        }
    }

    /// Get all arguments (GET + POST combined).
    pub fn all_args(&self) -> Vec<(&str, &str)> {
        let mut all = self.args_get.all();
        all.extend(self.args_post.all());
        all
    }
}
