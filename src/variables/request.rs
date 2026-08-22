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
    /// Multipart part headers (key = part name, value = full header line),
    /// populated by the multipart body processor. Mirrors ModSecurity's
    /// `MULTIPART_PART_HEADERS` collection.
    pub multipart_part_headers: HashMapCollection,
    /// Uploaded files (key = part name, value = client-supplied filename),
    /// populated by the multipart body processor. Backs `FILES`/`FILES_NAMES`.
    pub files: HashMapCollection,
    /// Name of the body processor that handled the request body
    /// (`MULTIPART`, `URLENCODED`, or empty when none ran). Backs
    /// `REQBODY_PROCESSOR`.
    pub body_processor: String,
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
        let lower = name.to_lowercase();
        if lower == "cookie" {
            self.parse_cookie_header(value);
        }
        self.headers.add(lower, value.to_string());
    }

    /// Parse a `Cookie` request header into the cookies collection.
    fn parse_cookie_header(&mut self, value: &str) {
        for pair in value.split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            match pair.split_once('=') {
                Some((k, v)) => self.cookies.add(k.trim().to_string(), v.trim().to_string()),
                None => self.cookies.add(pair.to_string(), String::new()),
            }
        }
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

    /// Parse a `multipart/form-data` body.
    ///
    /// Populates `args_post` from form fields, `files` from file parts, and
    /// `multipart_part_headers` with every part header line keyed by the part
    /// name (ModSecurity `MULTIPART_PART_HEADERS` semantics). Returns `false`
    /// when no boundary parameter can be extracted from the Content-Type.
    pub fn parse_multipart_body(&mut self, content_type: &str) -> bool {
        let Some(boundary) = extract_multipart_boundary(content_type) else {
            return false;
        };
        let body = self.body_str();
        let delimiter = format!("--{boundary}");

        let mut sections = body.split(delimiter.as_str());
        // Everything before the first boundary is preamble; discard it.
        let _preamble = sections.next();

        for section in sections {
            if section.starts_with("--") {
                // Closing delimiter (`--boundary--`); anything after is epilogue.
                break;
            }
            // The boundary line ends with CRLF before the part headers.
            let section = section
                .strip_prefix("\r\n")
                .or_else(|| section.strip_prefix("\n"))
                .unwrap_or(section);

            // Headers are separated from the part content by a blank line.
            let (head, content) = match section.split_once("\r\n\r\n") {
                Some(split) => split,
                None => match section.split_once("\n\n") {
                    Some(split) => split,
                    None => (section, ""),
                },
            };
            // The CRLF before the next boundary belongs to the framing, not
            // the content.
            let content = content
                .strip_suffix("\r\n")
                .or_else(|| content.strip_suffix("\n"))
                .unwrap_or(content);

            let mut part_name: Option<String> = None;
            let mut filename: Option<String> = None;
            let mut header_lines: Vec<String> = Vec::new();

            for line in head.lines() {
                let line = line.trim_end_matches('\r');
                if line.is_empty() {
                    continue;
                }
                header_lines.push(line.to_string());
                if let Some((hname, hval)) = line.split_once(':') {
                    if hname.trim().eq_ignore_ascii_case("content-disposition") {
                        part_name = extract_disposition_param(hval, "name");
                        filename = extract_disposition_param(hval, "filename");
                    }
                }
            }

            let Some(name) = part_name else {
                // A part without a Content-Disposition name cannot be
                // addressed by any collection key; skip it.
                continue;
            };

            for line in header_lines {
                self.multipart_part_headers.add(name.clone(), line);
            }
            if let Some(fname) = filename {
                self.files.add(name, fname);
            } else {
                self.args_post.add(name, content.to_string());
            }
        }

        self.body_processor = "MULTIPART".to_string();
        true
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

/// Extract the `boundary` parameter from a multipart Content-Type value.
fn extract_multipart_boundary(content_type: &str) -> Option<String> {
    for param in content_type.split(';').skip(1) {
        let param = param.trim();
        if let Some((key, value)) = param.split_once('=') {
            if key.trim().eq_ignore_ascii_case("boundary") {
                let value = value.trim().trim_matches('"');
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

/// Extract a parameter value (e.g. `name`, `filename`) from a
/// Content-Disposition header value.
fn extract_disposition_param(header_value: &str, param: &str) -> Option<String> {
    for part in header_value.split(';') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            if key.trim().eq_ignore_ascii_case(param) {
                return Some(value.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cookie_header() {
        let mut req = RequestData::new();
        req.add_header("Cookie", "session=abc123; theme=dark; bare");
        assert_eq!(req.cookies.get("session"), Some(vec!["abc123"]));
        assert_eq!(req.cookies.get("theme"), Some(vec!["dark"]));
        assert_eq!(req.cookies.get("bare"), Some(vec![""]));
    }

    #[test]
    fn test_parse_multipart_body_fields_and_headers() {
        let mut req = RequestData::new();
        let body = "--XyZ\r\n\
                    Content-Disposition: form-data; name=\"field1\"\r\n\
                    \r\n\
                    value1\r\n\
                    --XyZ\r\n\
                    Content-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    file contents\r\n\
                    --XyZ--\r\n";
        req.append_body(body.as_bytes());
        assert!(req.parse_multipart_body("multipart/form-data; boundary=XyZ"));

        // Form field lands in ARGS_POST.
        assert_eq!(req.args_post.get("field1"), Some(vec!["value1"]));
        // File part does NOT land in ARGS_POST but in FILES.
        assert_eq!(req.args_post.get("upload"), None);
        assert_eq!(req.files.get("upload"), Some(vec!["a.txt"]));

        // Every part header line is recorded under the part name.
        let field1_headers = req.multipart_part_headers.get("field1").unwrap();
        assert_eq!(field1_headers, vec!["Content-Disposition: form-data; name=\"field1\""]);
        let upload_headers = req.multipart_part_headers.get("upload").unwrap();
        assert!(upload_headers.contains(&"Content-Type: text/plain"));
        assert_eq!(req.body_processor, "MULTIPART");
    }

    #[test]
    fn test_parse_multipart_body_quoted_boundary_and_lf_only() {
        let mut req = RequestData::new();
        let body = "--b1\nContent-Disposition: form-data; name=\"k\"\n\nv\n--b1--\n";
        req.append_body(body.as_bytes());
        assert!(req.parse_multipart_body("multipart/form-data; boundary=\"b1\""));
        assert_eq!(req.args_post.get("k"), Some(vec!["v"]));
    }

    #[test]
    fn test_parse_multipart_body_missing_boundary() {
        let mut req = RequestData::new();
        req.append_body(b"irrelevant");
        assert!(!req.parse_multipart_body("multipart/form-data"));
        assert!(req.body_processor.is_empty());
    }
}
