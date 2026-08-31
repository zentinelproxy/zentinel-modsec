//! Request data for variable resolution.

use super::collection::{Collection, HashMapCollection};
use super::json::JsonNode;
use std::borrow::Cow;

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
    /// (`MULTIPART`, `URLENCODED`, `JSON`, or empty when none ran). Backs
    /// `REQBODY_PROCESSOR`.
    pub body_processor: String,
    /// Why the body processor could not process the body, if it failed.
    ///
    /// Backs `REQBODY_ERROR` (1 when set, 0 otherwise) and
    /// `REQBODY_ERROR_MSG`. CRS rule 200002 blocks on this, which only works
    /// if a failed parse is observable: a strict parser rejecting a payload
    /// that the origin application happily accepts is a bypass when it
    /// happens quietly.
    pub body_error: Option<String>,
    /// Request body.
    pub body: Vec<u8>,
    /// Client IP address.
    pub client_ip: String,
    /// Client port.
    pub client_port: u16,
    /// Server name.
    pub server_name: String,
    /// Local address the connection was accepted on. Backs `SERVER_ADDR`.
    pub server_addr: String,
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
                let key = form_decode(key);
                let value = form_decode(value);
                self.args_get.add(key, value);
            } else if !pair.is_empty() {
                let key = form_decode(pair);
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
                let key = form_decode(key);
                let value = form_decode(value);
                self.args_post.add(key, value);
            } else if !pair.is_empty() {
                // A parameter with no `=` is a name with an empty value, which
                // is how application frameworks parse it. Dropping it here was
                // a bypass: percent-encoding the `=` leaves a body with no
                // literal separator, so the whole body became invisible to
                // ARGS and ARGS_NAMES while the origin still saw a parameter.
                // The query-string parser has always handled this shape.
                self.args_post.add(form_decode(pair), String::new());
            }
        }
    }

    /// Parse a JSON body into `args_post`, mirroring ModSecurity's JSON
    /// request body processor.
    ///
    /// Every scalar in the document becomes one argument named by its path,
    /// prefixed with `json.` and joined with `.`, with array indices as path
    /// segments — the naming libmodsecurity uses, so CRS exclusions written as
    /// `ARGS:json.user.name` keep working:
    ///
    /// ```text
    /// {"user": {"name": "bob"}, "tags": ["a", "b"]}
    ///   -> json.user.name = bob
    ///      json.tags.0    = a
    ///      json.tags.1    = b
    /// ```
    ///
    /// Returns `Ok(())` on success, or the reason the body could not be
    /// processed. The caller must surface that reason rather than treating it
    /// as an empty body: a strict parser rejecting a payload that the origin
    /// application accepts is a bypass if it happens quietly.
    pub fn parse_json_body(&mut self) -> Result<(), String> {
        self.body_processor = "JSON".to_string();

        // A body that is empty or only whitespace has nothing to inspect, and
        // is not a parse failure. Clients legitimately send an empty body with
        // `Content-Type: application/json` on POST and DELETE; reporting that
        // as an error would make CRS rule 200002 block them.
        if self.body.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(());
        }

        let value: JsonNode = match serde_json::from_slice(&self.body) {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("JSON parsing error: {e}");
                self.body_error = Some(msg.clone());
                return Err(msg);
            }
        };

        let mut count = 0usize;
        let mut path = String::from("json");
        let truncated = flatten_json(&value, &mut path, &mut self.args_post, &mut count, 0);

        if truncated {
            let msg = format!(
                "JSON body exceeded processing limits ({MAX_JSON_ARGS} arguments or \
                 {MAX_JSON_DEPTH} levels of nesting); only part of the body was inspected"
            );
            self.body_error = Some(msg.clone());
            return Err(msg);
        }

        Ok(())
    }

    /// Parse an XML body, flattening element text and attributes into
    /// `args_post`.
    ///
    /// ModSecurity exposes XML through an XPath-selected `XML:` variable. That
    /// needs an XPath engine, which this does not have — so instead each text
    /// node and attribute becomes an argument named by its element path,
    /// prefixed `xml.`:
    ///
    /// ```text
    /// <order><item id="7">widget</item></order>
    ///   -> xml.order.item      = widget
    ///      xml.order.item.@id  = 7
    /// ```
    ///
    /// That is not ModSecurity-compatible naming, and rules written against
    /// `XML:/order/item` will not match it. It is chosen because the
    /// alternative was leaving XML bodies uninspected entirely: with this,
    /// `SecRule ARGS "@detectSQLi"` covers XML payloads the same way it covers
    /// form and JSON ones, which is what the common rulesets actually do.
    ///
    /// The whole document's text is also available as `REQUEST_BODY`.
    pub fn parse_xml_body(&mut self) -> Result<(), String> {
        use quick_xml::events::Event;

        self.body_processor = "XML".to_string();

        if self.body.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(());
        }

        let mut reader = quick_xml::Reader::from_reader(self.body.as_slice());
        reader.config_mut().check_end_names = true;

        let mut path: Vec<String> = Vec::new();
        // Text arrives in fragments, split around entity references. Buffering
        // per element and flushing on the closing tag keeps a value whole: a
        // payload written as `UNION&#32;SELECT` would otherwise be split into
        // pieces small enough for every rule to miss.
        let mut text: Vec<String> = Vec::new();
        let mut count = 0usize;
        let mut unresolved_entity: Option<String> = None;
        let mut buf = Vec::new();

        macro_rules! cap {
            ($name:expr, $value:expr) => {
                if push_xml_arg(&$name, $value, &mut self.args_post, &mut count) {
                    let msg = xml_limit_message();
                    self.body_error = Some(msg.clone());
                    return Err(msg);
                }
            };
        }

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                    if path.len() >= MAX_XML_DEPTH {
                        let msg = format!(
                            "XML body exceeded {MAX_XML_DEPTH} levels of nesting; \
                             only part of the body was inspected"
                        );
                        self.body_error = Some(msg.clone());
                        return Err(msg);
                    }
                    path.push(decode_name(e.name().as_ref()));
                    text.push(String::new());

                    for attr in e.attributes().flatten() {
                        let attr_name = decode_name(attr.key.as_ref());
                        let value = attr
                            .decoded_and_normalized_value(
                                quick_xml::XmlVersion::Implicit1_0,
                                reader.decoder(),
                            )
                            .map(|v| v.into_owned())
                            .unwrap_or_default();
                        let name = format!("xml.{}.@{}", path.join("."), attr_name);
                        cap!(name, value);
                    }
                }
                Ok(Event::End(_)) => {
                    if let Some(collected) = text.pop() {
                        let trimmed = collected.trim();
                        if !trimmed.is_empty() && !path.is_empty() {
                            let name = format!("xml.{}", path.join("."));
                            cap!(name, trimmed.to_string());
                        }
                    }
                    path.pop();
                }
                Ok(Event::Text(e)) => {
                    if let (Some(current), Ok(t)) = (text.last_mut(), e.decode()) {
                        current.push_str(t.as_ref());
                    }
                }
                Ok(Event::CData(e)) => {
                    // CDATA is text that is deliberately not markup, and a
                    // classic place to hide a payload.
                    if let Some(current) = text.last_mut() {
                        current.push_str(&String::from_utf8_lossy(e.as_ref()));
                    }
                }
                Ok(Event::GeneralRef(e)) => {
                    let name = e.decode().map(|n| n.into_owned()).unwrap_or_default();
                    match resolve_entity(&name) {
                        Some(resolved) => {
                            if let Some(current) = text.last_mut() {
                                current.push_str(&resolved);
                            }
                        }
                        None => {
                            // A custom entity. Expanding it is how XXE and
                            // billion-laughs work, so this deliberately does
                            // not. But the origin application may expand it,
                            // and content this engine cannot see is content it
                            // cannot inspect -- so say so rather than treat
                            // the document as fully examined.
                            unresolved_entity.get_or_insert(name);
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(e) => {
                    let msg = format!("XML parsing error: {e}");
                    self.body_error = Some(msg.clone());
                    return Err(msg);
                }
            }
            buf.clear();
        }

        // Elements left open at end of input mean the document was cut short.
        // quick-xml reports EOF rather than an error for this, so a truncated
        // body would otherwise look like a complete one that simply had less
        // in it.
        if !path.is_empty() {
            let msg = format!(
                "XML body ended with {} element(s) still open; the document is truncated \
                 and was only partly inspected",
                path.len()
            );
            self.body_error = Some(msg.clone());
            return Err(msg);
        }

        if let Some(name) = unresolved_entity {
            let msg = format!(
                "XML body references the undeclared or custom entity '&{name};', which is \
                 not expanded (expanding it is how XXE and entity-expansion attacks work). \
                 Any content it carries was not inspected."
            );
            self.body_error = Some(msg.clone());
            return Err(msg);
        }

        Ok(())
    }

    /// Get all arguments (GET + POST combined).
    pub fn all_args(&self) -> Vec<(&str, &str)> {
        let mut all = self.args_get.all();
        all.extend(self.args_post.all());
        all
    }
}

/// Most arguments extracted from a single XML body.
const MAX_XML_ARGS: usize = 4096;

/// Deepest element nesting the XML processor will descend.
///
/// quick-xml is a pull parser and does not recurse, so this bounds work and
/// argument-name length rather than stack depth.
const MAX_XML_DEPTH: usize = 64;

fn xml_limit_message() -> String {
    format!(
        "XML body exceeded {MAX_XML_ARGS} extracted values; only part of the \
         body was inspected"
    )
}

/// Resolve an entity reference this engine is willing to expand.
///
/// The five predefined XML entities and numeric character references only.
/// Custom entities declared in an internal DTD subset are deliberately not
/// resolved: expanding those is precisely the mechanism behind XXE and
/// billion-laughs, and no amount of care makes expanding attacker-supplied
/// entity definitions safe.
fn resolve_entity(name: &str) -> Option<String> {
    if let Some(predefined) = quick_xml::escape::resolve_predefined_entity(name) {
        return Some(predefined.to_string());
    }
    // Numeric character references: &#65; and &#x41;.
    let digits = name.strip_prefix('#')?;
    let code = match digits.strip_prefix(['x', 'X']) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<u32>().ok()?,
    };
    char::from_u32(code).map(|c| c.to_string())
}

/// Element and attribute names are ASCII in practice; lossy decoding avoids
/// rejecting a document over a malformed name when the payload is elsewhere.
fn decode_name(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).to_string()
}

/// Decode one component of `application/x-www-form-urlencoded` input.
///
/// In that encoding `+` denotes a space -- it is what a browser emits for a
/// space in a submitted form -- so decoding only percent-escapes leaves the
/// argument holding a literal `+` where the origin application will see a
/// space. Any rule matching a payload that contains whitespace then misses,
/// which is a bypass rather than a coverage gap: the same request reaches the
/// application as spaces either way.
///
/// The `+` substitution happens *before* percent-decoding, so a plus that was
/// genuinely sent as `%2B` survives as a plus instead of becoming a space.
fn form_decode(component: &str) -> String {
    let plus_decoded: Cow<'_, str> = if component.as_bytes().contains(&b'+') {
        Cow::Owned(component.replace('+', " "))
    } else {
        Cow::Borrowed(component)
    };
    percent_encoding::percent_decode_str(&plus_decoded)
        .decode_utf8_lossy()
        .into_owned()
}

/// Record one extracted XML value. Returns `true` once the cap is hit.
fn push_xml_arg(
    name: &str,
    value: String,
    args: &mut HashMapCollection,
    count: &mut usize,
) -> bool {
    if *count >= MAX_XML_ARGS {
        return true;
    }
    *count += 1;
    args.add(name.to_string(), value);
    false
}

/// Most arguments extracted from a single JSON body.
///
/// A hostile body can be small on the wire and still expand into an enormous
/// number of arguments — `[[[...]]]` or a long array of scalars — each of
/// which would then be run through every rule's operator. The cap bounds that
/// work; exceeding it is reported as a body-processor error rather than
/// silently truncating, since a partially inspected body is not a safe body.
const MAX_JSON_ARGS: usize = 4096;

/// Deepest JSON nesting the flattener will descend.
///
/// `serde_json` already refuses to *parse* beyond its own recursion limit;
/// this bounds the separate recursion done here.
const MAX_JSON_DEPTH: usize = 64;

/// Flatten a JSON value into `args`, naming each scalar by its path.
///
/// `path` is the prefix built so far and is restored before returning, so one
/// buffer is reused for the whole document. Returns `true` if a limit was hit
/// and the result is therefore incomplete.
fn flatten_json(
    value: &JsonNode,
    path: &mut String,
    args: &mut HashMapCollection,
    count: &mut usize,
    depth: usize,
) -> bool {
    if depth > MAX_JSON_DEPTH {
        return true;
    }

    match value {
        JsonNode::Object(entries) => {
            // Duplicate keys produce repeated entries under the same argument
            // name, so every value a client sent is inspected. Keeping only
            // one would let a parser differential hide a payload.
            for (key, child) in entries {
                let restore = path.len();
                path.push('.');
                path.push_str(key);
                let truncated = flatten_json(child, path, args, count, depth + 1);
                path.truncate(restore);
                if truncated {
                    return true;
                }
            }
            false
        }
        JsonNode::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let restore = path.len();
                path.push('.');
                path.push_str(&index.to_string());
                let truncated = flatten_json(child, path, args, count, depth + 1);
                path.truncate(restore);
                if truncated {
                    return true;
                }
            }
            false
        }
        // Scalars are the leaves that become arguments. `null` contributes an
        // empty value rather than being skipped, so a rule testing for the
        // presence of a key still sees it.
        JsonNode::String(s) => push_json_arg(path, s.clone(), args, count),
        JsonNode::Number(n) => push_json_arg(path, n.clone(), args, count),
        JsonNode::Bool(b) => push_json_arg(path, b.to_string(), args, count),
        JsonNode::Null => push_json_arg(path, String::new(), args, count),
    }
}

/// Record one flattened scalar. Returns `true` once the argument cap is hit.
fn push_json_arg(
    path: &str,
    value: String,
    args: &mut HashMapCollection,
    count: &mut usize,
) -> bool {
    if *count >= MAX_JSON_ARGS {
        return true;
    }
    *count += 1;
    args.add(path.to_string(), value);
    false
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
        assert_eq!(
            field1_headers,
            vec!["Content-Disposition: form-data; name=\"field1\""]
        );
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
