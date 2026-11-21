//! Variable resolution engine.

use super::collection::{Collection, HashMapCollection};
use super::{RequestData, ResponseData, TxCollection};
use crate::parser::{Selection, VariableName, VariableSpec, XmlTarget};
use once_cell::sync::Lazy;
use regex::Regex;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;

/// The name of one resolved value, kept in parts until someone needs the text.
///
/// Most values a rule resolves never match, so their names are never read.
/// `Display` renders the same text the resolver used to build eagerly:
/// `REQUEST_URI` for a scalar, `ARGS:id` for a collection member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedName<'a> {
    collection: &'static str,
    member: Option<Cow<'a, str>>,
}

impl<'a> ResolvedName<'a> {
    fn scalar(name: &'static str) -> Self {
        Self {
            collection: name,
            member: None,
        }
    }

    fn member(collection: &'static str, member: impl Into<Cow<'a, str>>) -> Self {
        Self {
            collection,
            member: Some(member.into()),
        }
    }
}

impl fmt::Display for ResolvedName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.collection)?;
        if let Some(member) = &self.member {
            f.write_str(":")?;
            f.write_str(member)?;
        }
        Ok(())
    }
}

/// One resolved value: its name and its text, borrowed where the request,
/// the response or TX already hold it.
pub type ResolvedValue<'a> = (ResolvedName<'a>, Cow<'a, str>);

/// A scalar variable's single value.
fn scalar<'a>(name: &'static str, value: impl Into<Cow<'a, str>>) -> Vec<ResolvedValue<'a>> {
    vec![(ResolvedName::scalar(name), value.into())]
}

/// Compile a regex written in rule text (an `ARGS:/.../` selection or a
/// `!ARGS:/.../` exclusion), once per pattern.
///
/// These used to be compiled on every evaluation, once per resolved key for an
/// exclusion. Compiling costs orders of magnitude more than matching: CRS
/// 942431's two `!ARGS_NAMES:/.../` exclusions took ~5.5ms per request on
/// clean traffic, for patterns that never change.
///
/// Patterns come only from loaded rules, so the cache is bounded by the rule
/// set. A pattern that does not compile is cached as `None` and never matches,
/// as before. `Regex` clones share the compiled program.
fn cached_regex(pattern: &str) -> Option<Regex> {
    static CACHE: Lazy<RwLock<HashMap<String, Option<Regex>>>> = Lazy::new(Default::default);
    if let Some(hit) = CACHE.read().unwrap_or_else(|e| e.into_inner()).get(pattern) {
        return hit.clone();
    }
    let compiled = Regex::new(pattern).ok();
    CACHE
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .entry(pattern.to_string())
        .or_insert(compiled)
        .clone()
}

/// Variable resolver for transaction context.
pub struct VariableResolver<'a> {
    request: &'a RequestData,
    response: &'a ResponseData,
    tx: &'a TxCollection,
    matched_var: Option<&'a str>,
    matched_vars: &'a [(String, String)],
    /// Carried alongside the other resolver inputs for symmetry; no variable
    /// reads it yet (`TX:0`..`TX:9` are served from the TX collection).
    #[allow(dead_code)]
    captures: &'a [String],
}

impl<'a> VariableResolver<'a> {
    /// Create a new resolver.
    pub fn new(
        request: &'a RequestData,
        response: &'a ResponseData,
        tx: &'a TxCollection,
        matched_var: Option<&'a str>,
        matched_vars: &'a [(String, String)],
        captures: &'a [String],
    ) -> Self {
        Self {
            request,
            response,
            tx,
            matched_var,
            matched_vars,
            captures,
        }
    }

    /// Resolve a variable specification to owned name and value pairs.
    pub fn resolve(&self, spec: &VariableSpec) -> Vec<(String, String)> {
        self.resolve_borrowed(spec)
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.into_owned()))
            .collect()
    }

    /// Resolve a variable specification to values without copying them.
    ///
    /// The values borrow from the request, the response and TX; the names
    /// borrow member keys from those and from `spec`. Nothing is formatted or
    /// cloned for a value until a caller asks for it, which rule evaluation
    /// does only for the values that match.
    pub fn resolve_borrowed<'s>(&self, spec: &'s VariableSpec) -> Vec<ResolvedValue<'s>>
    where
        'a: 's,
    {
        let mut values = self.resolve_variable(spec.name, &spec.selection);

        // Apply exclusions
        if !spec.exclusions.is_empty() {
            values.retain(|(name, _)| {
                !spec
                    .exclusions
                    .iter()
                    .any(|e| exclusion_matches(name.collection, name.member.as_deref(), e))
            });
        }
        values
    }

    /// Resolve a variable by name.
    fn resolve_variable<'s>(
        &self,
        name: VariableName,
        selection: &'s Option<Selection>,
    ) -> Vec<ResolvedValue<'s>>
    where
        'a: 's,
    {
        let request: &'a RequestData = self.request;
        let response: &'a ResponseData = self.response;
        match name {
            // Request variables
            VariableName::RequestUri => scalar("REQUEST_URI", &request.uri),
            VariableName::RequestUriRaw => scalar("REQUEST_URI_RAW", &request.uri_raw),
            VariableName::RequestMethod => scalar("REQUEST_METHOD", &request.method),
            VariableName::RequestProtocol => scalar("REQUEST_PROTOCOL", &request.protocol),
            VariableName::QueryString => scalar("QUERY_STRING", &request.query_string),
            VariableName::RequestFilename => scalar("REQUEST_FILENAME", &request.path),
            VariableName::RequestLine => {
                // The request line as it arrived. CRS 920100 tests this with a
                // negated regex, so leaving it unresolved made that rule match
                // every request rather than none.
                let uri = if request.uri_raw.is_empty() {
                    &request.uri
                } else {
                    &request.uri_raw
                };
                scalar(
                    "REQUEST_LINE",
                    format!("{} {} {}", request.method, uri, request.protocol),
                )
            }
            VariableName::RequestBasename => {
                // Final path segment. ModSecurity splits on both separators, so
                // a Windows-style path does not hide the basename.
                let basename = self.request.path.rsplit(['/', '\\']).next().unwrap_or("");
                scalar("REQUEST_BASENAME", basename)
            }
            VariableName::ArgsCombinedSize => {
                let size: usize = [&request.args_get, &request.args_post]
                    .iter()
                    .flat_map(|c| c.all())
                    .map(|(name, value)| name.len() + value.len())
                    .sum();
                scalar("ARGS_COMBINED_SIZE", size.to_string())
            }
            // The raw body, always, whichever body processor ran or none.
            // This is why ctl:forceRequestBodyVariable is accepted as a no-op.
            VariableName::RequestBody => scalar("REQUEST_BODY", request.body_str()),
            VariableName::RequestBodyLength => {
                scalar("REQUEST_BODY_LENGTH", request.body_length().to_string())
            }

            // Collections
            VariableName::Args => self.resolve_collection_from_all_args(selection),
            VariableName::ArgsGet => {
                self.resolve_collection(&request.args_get, "ARGS_GET", selection)
            }
            VariableName::ArgsPost => {
                self.resolve_collection(&request.args_post, "ARGS_POST", selection)
            }
            VariableName::ArgsNames => self.resolve_collection_names(
                &[&request.args_get, &request.args_post],
                "ARGS_NAMES",
                selection,
            ),
            VariableName::ArgsGetNames => {
                self.resolve_collection_names(&[&request.args_get], "ARGS_GET_NAMES", selection)
            }
            VariableName::ArgsPostNames => {
                self.resolve_collection_names(&[&request.args_post], "ARGS_POST_NAMES", selection)
            }
            VariableName::RequestHeaders => {
                self.resolve_collection_ci(&request.headers, "REQUEST_HEADERS", selection)
            }
            VariableName::RequestHeadersNames => self.resolve_collection_names(
                &[&request.headers],
                "REQUEST_HEADERS_NAMES",
                selection,
            ),
            VariableName::RequestCookies => {
                self.resolve_collection(&request.cookies, "REQUEST_COOKIES", selection)
            }
            VariableName::RequestCookiesNames => self.resolve_collection_names(
                &[&request.cookies],
                "REQUEST_COOKIES_NAMES",
                selection,
            ),

            // Multipart body processor results
            VariableName::MultipartPartHeaders => self.resolve_collection(
                &request.multipart_part_headers,
                "MULTIPART_PART_HEADERS",
                selection,
            ),
            VariableName::Files => self.resolve_collection(&request.files, "FILES", selection),
            VariableName::FilesNames => {
                self.resolve_collection_names(&[&request.files], "FILES_NAMES", selection)
            }
            VariableName::FilesSizes => {
                self.resolve_collection(&request.files_sizes, "FILES_SIZES", selection)
            }
            // Always present -- "0" without uploads -- so a rule comparing the
            // total against a limit, or against 0, finds a value, as in
            // ModSecurity.
            VariableName::FilesCombinedSize => scalar(
                "FILES_COMBINED_SIZE",
                request.files_combined_size.to_string(),
            ),
            VariableName::UniqueId => {
                if request.unique_id.is_empty() {
                    vec![]
                } else {
                    scalar("UNIQUE_ID", &request.unique_id)
                }
            }
            VariableName::ReqBodyProcessor => {
                if request.body_processor.is_empty() {
                    vec![]
                } else {
                    scalar("REQBODY_PROCESSOR", &request.body_processor)
                }
            }

            // A body the processor could not handle. These resolved to nothing
            // before, so CRS rule 200002 (`SecRule REQBODY_ERROR "!@eq 0"`)
            // could never fire and a rejected body passed unexamined and
            // unreported.
            //
            // REQBODY_ERROR always has a value -- "0" when the body processed
            // cleanly -- because a rule comparing it against 0 must be able to
            // find it. REQBODY_ERROR_MSG is absent unless there is a message,
            // matching ModSecurity.
            VariableName::ReqBodyError | VariableName::ReqBodyProcessorError => {
                let flag = if request.body_error.is_some() {
                    "1"
                } else {
                    "0"
                };
                scalar("REQBODY_ERROR", flag)
            }
            VariableName::ReqBodyErrorMsg | VariableName::ReqBodyProcessorErrorMsg => {
                match &request.body_error {
                    Some(msg) => scalar("REQBODY_ERROR_MSG", msg),
                    None => vec![],
                }
            }

            // Response variables
            VariableName::ResponseStatus => scalar("RESPONSE_STATUS", response.status.to_string()),
            VariableName::ResponseBody => scalar("RESPONSE_BODY", response.body_str()),
            VariableName::ResponseContentType => {
                scalar("RESPONSE_CONTENT_TYPE", &response.content_type)
            }
            VariableName::ResponseHeaders => {
                self.resolve_collection_ci(&response.headers, "RESPONSE_HEADERS", selection)
            }

            // TX collection
            VariableName::Xml => self.resolve_xml(selection),

            VariableName::Tx => self.resolve_tx_collection(selection),

            // Client/Server info
            VariableName::RemoteAddr => scalar("REMOTE_ADDR", &request.client_ip),
            VariableName::RemotePort => scalar("REMOTE_PORT", request.client_port.to_string()),
            VariableName::ServerName => scalar("SERVER_NAME", &request.server_name),
            VariableName::ServerAddr => scalar("SERVER_ADDR", &request.server_addr),
            VariableName::ServerPort => scalar("SERVER_PORT", request.server_port.to_string()),

            // Matched variables
            VariableName::MatchedVar => {
                if let Some(v) = self.matched_var {
                    scalar("MATCHED_VAR", v)
                } else {
                    vec![]
                }
            }
            VariableName::MatchedVars => {
                let matched_vars: &'a [(String, String)] = self.matched_vars;
                matched_vars
                    .iter()
                    .map(|(k, v)| {
                        (
                            ResolvedName::member("MATCHED_VARS", k.as_str()),
                            Cow::Borrowed(v.as_str()),
                        )
                    })
                    .collect()
            }
            VariableName::MatchedVarName => match self.matched_vars.last() {
                Some((name, _)) => scalar("MATCHED_VAR_NAME", name),
                None => vec![],
            },
            VariableName::MatchedVarsNames => {
                let matched_vars: &'a [(String, String)] = self.matched_vars;
                matched_vars
                    .iter()
                    .map(|(k, _)| {
                        (
                            ResolvedName::member("MATCHED_VARS_NAMES", k.as_str()),
                            Cow::Borrowed(k.as_str()),
                        )
                    })
                    .collect()
            }

            // Default - empty
            _ => vec![],
        }
    }

    /// Resolve a collection with optional selection.
    fn resolve_collection<'s>(
        &self,
        collection: &'s HashMapCollection,
        prefix: &'static str,
        selection: &'s Option<Selection>,
    ) -> Vec<ResolvedValue<'s>> {
        self.resolve_collection_inner(collection, prefix, selection, false)
    }

    /// Resolve a collection where keys are matched case-insensitively (HTTP headers).
    fn resolve_collection_ci<'s>(
        &self,
        collection: &'s HashMapCollection,
        prefix: &'static str,
        selection: &'s Option<Selection>,
    ) -> Vec<ResolvedValue<'s>> {
        self.resolve_collection_inner(collection, prefix, selection, true)
    }

    fn resolve_collection_inner<'s>(
        &self,
        collection: &'s HashMapCollection,
        prefix: &'static str,
        selection: &'s Option<Selection>,
        lowercase_key: bool,
    ) -> Vec<ResolvedValue<'s>> {
        match selection {
            Some(Selection::Key(key)) => {
                let lookup = if lowercase_key && key.bytes().any(|b| b.is_ascii_uppercase()) {
                    Cow::Owned(key.to_ascii_lowercase())
                } else {
                    Cow::Borrowed(key.as_str())
                };
                if let Some(values) = collection.get(&lookup) {
                    values
                        .into_iter()
                        .map(|v| (ResolvedName::member(prefix, key.as_str()), Cow::Borrowed(v)))
                        .collect()
                } else {
                    vec![]
                }
            }
            Some(Selection::Regex(pattern)) => {
                if let Some(re) = cached_regex(pattern) {
                    members(prefix, collection.get_regex(&re))
                } else {
                    vec![]
                }
            }
            None => members(prefix, collection.all()),
        }
    }

    /// Resolve ARGS collection (GET + POST combined).
    /// Resolve an `XML:` target against the flattened XML body.
    ///
    /// The XML body processor flattens element text to `xml.<path>` and
    /// attributes to `xml.<path>.@<name>` in `ARGS`. `XML:/*` and `XML://@*`
    /// are exactly those two sets, so they are answered from the flattening
    /// rather than by evaluating XPath.
    ///
    /// Values are reported under their XPath-style name -- `xml.order.item.@id`
    /// is reported as `XML:/order/item/@id` -- so `%{MATCHED_VAR_NAME}` in a
    /// rule's `logdata` names the node the way the rule addressed it.
    fn resolve_xml(&self, selection: &Option<Selection>) -> Vec<ResolvedValue<'a>> {
        let Some(target) = XmlTarget::from_selection(selection.as_ref()) else {
            // An XPath expression this engine cannot express. Reported when the
            // rules load, so there is nothing to say per request.
            return vec![];
        };

        let request: &'a RequestData = self.request;
        request
            .args_post
            .all()
            .into_iter()
            .filter_map(|(name, value)| {
                let path = name.strip_prefix("xml.")?;
                // An XML element name cannot begin with `@`, so `.@` only ever
                // marks the attribute segment this processor appends.
                let is_attribute = path.contains(".@");
                let wanted = match target {
                    XmlTarget::Elements => !is_attribute,
                    XmlTarget::Attributes => is_attribute,
                    XmlTarget::All => true,
                };
                if !wanted {
                    return None;
                }
                Some((
                    ResolvedName::member("XML", format!("/{}", path.replace('.', "/"))),
                    Cow::Borrowed(value),
                ))
            })
            .collect()
    }

    fn resolve_collection_from_all_args<'s>(
        &self,
        selection: &'s Option<Selection>,
    ) -> Vec<ResolvedValue<'s>>
    where
        'a: 's,
    {
        let request: &'a RequestData = self.request;
        let mut result = self.resolve_collection(&request.args_get, "ARGS", selection);
        result.extend(self.resolve_collection(&request.args_post, "ARGS", selection));
        result
    }

    /// Resolve a `*_NAMES` collection: the values are the keys of the backing
    /// collection(s), one entry per stored value (duplicates preserved,
    /// matching ModSecurity).
    fn resolve_collection_names<'s>(
        &self,
        collections: &[&'s HashMapCollection],
        prefix: &'static str,
        selection: &Option<Selection>,
    ) -> Vec<ResolvedValue<'s>> {
        let mut result = Vec::new();
        for collection in collections {
            for (key, _) in collection.all() {
                let selected = match selection {
                    Some(Selection::Key(sel)) => key.eq_ignore_ascii_case(sel),
                    Some(Selection::Regex(pattern)) => cached_regex(pattern)
                        .map(|re| re.is_match(key))
                        .unwrap_or(false),
                    None => true,
                };
                if selected {
                    result.push((ResolvedName::member(prefix, key), Cow::Borrowed(key)));
                }
            }
        }
        result
    }

    /// Resolve TX collection.
    fn resolve_tx_collection<'s>(&self, selection: &'s Option<Selection>) -> Vec<ResolvedValue<'s>>
    where
        'a: 's,
    {
        let tx: &'a TxCollection = self.tx;
        match selection {
            Some(Selection::Key(key)) => {
                if let Some(values) = tx.get(key) {
                    values
                        .into_iter()
                        .map(|v| (ResolvedName::member("TX", key.as_str()), Cow::Borrowed(v)))
                        .collect()
                } else {
                    vec![]
                }
            }
            Some(Selection::Regex(pattern)) => {
                if let Some(re) = cached_regex(pattern) {
                    members("TX", tx.get_regex(&re))
                } else {
                    vec![]
                }
            }
            None => members("TX", tx.all()),
        }
    }
}

/// Name every `(key, value)` of a collection as `PREFIX:key`.
fn members<'s>(prefix: &'static str, entries: Vec<(&'s str, &'s str)>) -> Vec<ResolvedValue<'s>> {
    entries
        .into_iter()
        .map(|(k, v)| (ResolvedName::member(prefix, k), Cow::Borrowed(v)))
        .collect()
}

/// Check whether a resolved variable key (e.g. `ARGS:password`) is excluded by
/// a target exclusion (`!TARGET` in a rule's variable list or in
/// `SecRuleUpdateTargetById`).
///
/// Supported exclusion forms, per ModSecurity:
/// - `COLLECTION:key` — excludes that member (key compared case-insensitively);
/// - `COLLECTION:/regex/` — excludes members whose key matches the regex;
/// - `COLLECTION` — excludes the entire collection.
fn exclusion_matches(key_coll: &str, key_member: Option<&str>, exclusion: &str) -> bool {
    match exclusion.split_once(':') {
        Some((excl_coll, excl_sel)) => {
            let Some(key_member) = key_member else {
                return false;
            };
            if !key_coll.eq_ignore_ascii_case(excl_coll) {
                return false;
            }
            if excl_sel.len() > 2 && excl_sel.starts_with('/') && excl_sel.ends_with('/') {
                cached_regex(&excl_sel[1..excl_sel.len() - 1])
                    .map(|re| re.is_match(key_member))
                    .unwrap_or(false)
            } else {
                key_member.eq_ignore_ascii_case(excl_sel)
            }
        }
        None => key_coll.eq_ignore_ascii_case(exclusion),
    }
}

#[cfg(test)]
mod tests {
    use super::cached_regex;

    /// `exclusion_matches` for a name in its rendered form.
    fn exclusion_matches(key: &str, exclusion: &str) -> bool {
        match key.split_once(':') {
            Some((collection, member)) => {
                super::exclusion_matches(collection, Some(member), exclusion)
            }
            None => super::exclusion_matches(key, None, exclusion),
        }
    }

    #[test]
    fn test_cached_regex_compiles_once_and_keeps_invalid_patterns_dead() {
        let a = cached_regex(r"^user_\d+$").expect("valid pattern");
        let b = cached_regex(r"^user_\d+$").expect("valid pattern");
        assert!(a.is_match("user_42") && b.is_match("user_42"));
        // An invalid pattern stays a never-matching selection, cached or not.
        assert!(cached_regex("(unclosed").is_none());
        assert!(cached_regex("(unclosed").is_none());
        assert!(!exclusion_matches("ARGS:x", "ARGS:/(unclosed/"));
    }

    #[test]
    fn test_exclusion_exact_key() {
        assert!(exclusion_matches("ARGS:password", "ARGS:password"));
        assert!(exclusion_matches("ARGS:Password", "ARGS:password"));
        // Must NOT be a prefix/substring match.
        assert!(!exclusion_matches("ARGS:password2", "ARGS:password"));
        assert!(!exclusion_matches("ARGS:xpassword", "ARGS:password"));
        // Different collection.
        assert!(!exclusion_matches(
            "REQUEST_COOKIES:password",
            "ARGS:password"
        ));
    }

    #[test]
    fn test_exclusion_regex_key() {
        // CRS pattern: SecRuleUpdateTargetById 941100 "!REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        assert!(exclusion_matches(
            "REQUEST_COOKIES:_ga_ABC123",
            r"REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        ));
        assert!(exclusion_matches(
            "REQUEST_COOKIES:_ga",
            r"REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        ));
        assert!(!exclusion_matches(
            "REQUEST_COOKIES:session",
            r"REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        ));
    }

    #[test]
    fn test_exclusion_whole_collection() {
        assert!(exclusion_matches("ARGS:anything", "ARGS"));
        assert!(!exclusion_matches("ARGS_NAMES:anything", "ARGS"));
    }
}
