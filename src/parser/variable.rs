//! Variable parsing for SecRule.
//!
//! Optimized with perfect hash function for O(1) variable name lookup.

use crate::error::{Error, Result};
use phf::phf_map;

/// A variable specification in a SecRule.
#[derive(Debug, Clone)]
pub struct VariableSpec {
    /// The variable name.
    pub name: VariableName,
    /// Optional selection (e.g., ARGS:foo or ARGS:/^user/).
    pub selection: Option<Selection>,
    /// Count mode (& prefix).
    pub count_mode: bool,
    /// Exclusions (e.g., !ARGS:foo).
    pub exclusions: Vec<String>,
}

/// Selection mode for collection variables.
#[derive(Debug, Clone)]
pub enum Selection {
    /// Static key selection (ARGS:foo).
    Key(String),
    /// Regex key selection (ARGS:/^user/).
    Regex(String),
}

/// Variable names supported by ModSecurity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VariableName {
    // Request variables
    Args, ArgsGet, ArgsPost, ArgsNames, ArgsGetNames, ArgsPostNames, ArgsCombinedSize,
    RequestUri, RequestUriRaw, RequestFilename, RequestBasename, RequestLine,
    RequestMethod, RequestProtocol, RequestHeaders, RequestHeadersNames,
    RequestCookies, RequestCookiesNames, RequestBody, RequestBodyLength, QueryString,

    // Response variables
    ResponseStatus, ResponseProtocol, ResponseHeaders, ResponseHeadersNames,
    ResponseBody, ResponseContentType, ResponseContentLength,

    // Server/Client info
    RemoteAddr, RemotePort, RemoteHost, RemoteUser,
    ServerAddr, ServerPort, ServerName,

    // Collections
    Tx, Session, Env, Ip, Global, Resource, User, Geo,

    // Matched data
    MatchedVar, MatchedVars, MatchedVarName, MatchedVarsNames,

    // Time variables
    Time, TimeEpoch, TimeDay, TimeHour, TimeMin, TimeSec, TimeWday, TimeMon, TimeYear,

    // Files
    Files, FilesSizes, FilesTmpnames, FilesCombinedSize, FilesNames,

    // Special
    UniqueId, InboundAnomalyScore, OutboundAnomalyScore, Duration,
    MultipartBoundaryQuoted, MultipartBoundaryWhitespace, MultipartDataAfter,
    MultipartDataBefore, MultipartFileLimitExceeded, MultipartHeaderFolding,
    MultipartInvalidHeaderFolding, MultipartInvalidPart, MultipartInvalidQuoting,
    MultipartLfLine, MultipartMissingSemicolon, MultipartStrictError,
    MultipartUnmatchedBoundary,

    // XML
    Xml,

    // Web server
    WebserverErrorLog, HighestSeverity, StatusLine, FullRequest, FullRequestLength,

    // Auth
    AuthType,

    // Request body processing
    ReqBodyProcessor, ReqBodyError, ReqBodyErrorMsg, ReqBodyProcessorError, ReqBodyProcessorErrorMsg,

    // Multipart strict
    MultipartStrictCheck,
}

/// Perfect hash map for O(1) variable name lookup.
static VARIABLE_MAP: phf::Map<&'static str, VariableName> = phf_map! {
    "ARGS" => VariableName::Args,
    "ARGS_GET" => VariableName::ArgsGet,
    "ARGS_POST" => VariableName::ArgsPost,
    "ARGS_NAMES" => VariableName::ArgsNames,
    "ARGS_GET_NAMES" => VariableName::ArgsGetNames,
    "ARGS_POST_NAMES" => VariableName::ArgsPostNames,
    "ARGS_COMBINED_SIZE" => VariableName::ArgsCombinedSize,
    "REQUEST_URI" => VariableName::RequestUri,
    "REQUEST_URI_RAW" => VariableName::RequestUriRaw,
    "REQUEST_FILENAME" => VariableName::RequestFilename,
    "REQUEST_BASENAME" => VariableName::RequestBasename,
    "REQUEST_LINE" => VariableName::RequestLine,
    "REQUEST_METHOD" => VariableName::RequestMethod,
    "REQUEST_PROTOCOL" => VariableName::RequestProtocol,
    "REQUEST_HEADERS" => VariableName::RequestHeaders,
    "REQUEST_HEADERS_NAMES" => VariableName::RequestHeadersNames,
    "REQUEST_COOKIES" => VariableName::RequestCookies,
    "REQUEST_COOKIES_NAMES" => VariableName::RequestCookiesNames,
    "REQUEST_BODY" => VariableName::RequestBody,
    "REQUEST_BODY_LENGTH" => VariableName::RequestBodyLength,
    "QUERY_STRING" => VariableName::QueryString,
    "RESPONSE_STATUS" => VariableName::ResponseStatus,
    "RESPONSE_PROTOCOL" => VariableName::ResponseProtocol,
    "RESPONSE_HEADERS" => VariableName::ResponseHeaders,
    "RESPONSE_HEADERS_NAMES" => VariableName::ResponseHeadersNames,
    "RESPONSE_BODY" => VariableName::ResponseBody,
    "RESPONSE_CONTENT_TYPE" => VariableName::ResponseContentType,
    "RESPONSE_CONTENT_LENGTH" => VariableName::ResponseContentLength,
    "REMOTE_ADDR" => VariableName::RemoteAddr,
    "REMOTE_PORT" => VariableName::RemotePort,
    "REMOTE_HOST" => VariableName::RemoteHost,
    "REMOTE_USER" => VariableName::RemoteUser,
    "SERVER_ADDR" => VariableName::ServerAddr,
    "SERVER_PORT" => VariableName::ServerPort,
    "SERVER_NAME" => VariableName::ServerName,
    "TX" => VariableName::Tx,
    "SESSION" => VariableName::Session,
    "ENV" => VariableName::Env,
    "IP" => VariableName::Ip,
    "GLOBAL" => VariableName::Global,
    "RESOURCE" => VariableName::Resource,
    "USER" => VariableName::User,
    "GEO" => VariableName::Geo,
    "MATCHED_VAR" => VariableName::MatchedVar,
    "MATCHED_VARS" => VariableName::MatchedVars,
    "MATCHED_VAR_NAME" => VariableName::MatchedVarName,
    "MATCHED_VARS_NAMES" => VariableName::MatchedVarsNames,
    "TIME" => VariableName::Time,
    "TIME_EPOCH" => VariableName::TimeEpoch,
    "TIME_DAY" => VariableName::TimeDay,
    "TIME_HOUR" => VariableName::TimeHour,
    "TIME_MIN" => VariableName::TimeMin,
    "TIME_SEC" => VariableName::TimeSec,
    "TIME_WDAY" => VariableName::TimeWday,
    "TIME_MON" => VariableName::TimeMon,
    "TIME_YEAR" => VariableName::TimeYear,
    "FILES" => VariableName::Files,
    "FILES_SIZES" => VariableName::FilesSizes,
    "FILES_TMPNAMES" => VariableName::FilesTmpnames,
    "FILES_COMBINED_SIZE" => VariableName::FilesCombinedSize,
    "FILES_NAMES" => VariableName::FilesNames,
    "UNIQUE_ID" => VariableName::UniqueId,
    "DURATION" => VariableName::Duration,
    "HIGHEST_SEVERITY" => VariableName::HighestSeverity,
    "STATUS_LINE" => VariableName::StatusLine,
    "FULL_REQUEST" => VariableName::FullRequest,
    "FULL_REQUEST_LENGTH" => VariableName::FullRequestLength,
    "AUTH_TYPE" => VariableName::AuthType,
    "XML" => VariableName::Xml,
    "REQBODY_PROCESSOR" => VariableName::ReqBodyProcessor,
    "REQBODY_ERROR" => VariableName::ReqBodyError,
    "REQBODY_ERROR_MSG" => VariableName::ReqBodyErrorMsg,
    "REQBODY_PROCESSOR_ERROR" => VariableName::ReqBodyProcessorError,
    "REQBODY_PROCESSOR_ERROR_MSG" => VariableName::ReqBodyProcessorErrorMsg,
    "MULTIPART_STRICT_ERROR" => VariableName::MultipartStrictCheck,
};

impl VariableName {
    /// Parse a variable name from a string (O(1) lookup).
    #[inline]
    pub fn from_str(s: &str) -> Option<Self> {
        // Fast path: check if already uppercase ASCII
        if s.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
            return VARIABLE_MAP.get(s).copied();
        }
        // Slow path: need to uppercase
        let mut buf = [0u8; 64];
        let len = s.len().min(64);
        for (i, b) in s.bytes().take(len).enumerate() {
            buf[i] = b.to_ascii_uppercase();
        }
        let upper = std::str::from_utf8(&buf[..len]).ok()?;
        VARIABLE_MAP.get(upper).copied()
    }

    /// Check if this variable is a collection.
    #[inline]
    pub fn is_collection(&self) -> bool {
        matches!(
            self,
            Self::Args | Self::ArgsGet | Self::ArgsPost | Self::ArgsNames
                | Self::RequestHeaders | Self::RequestHeadersNames
                | Self::RequestCookies | Self::RequestCookiesNames
                | Self::ResponseHeaders | Self::ResponseHeadersNames
                | Self::Tx | Self::Session | Self::Env | Self::Ip
                | Self::Global | Self::Resource | Self::User | Self::Geo
                | Self::MatchedVars | Self::MatchedVarsNames
                | Self::Files | Self::FilesSizes | Self::FilesTmpnames | Self::FilesNames
        )
    }
}

/// Parse a variable specification string.
#[inline]
pub fn parse_variables(input: &str) -> Result<Vec<VariableSpec>> {
    let mut variables = Vec::with_capacity(4);
    let mut exclusions: Vec<String> = Vec::new();

    // Split by | for OR conditions
    for part in input.split('|') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // Handle exclusions (!VAR)
        if part.starts_with('!') {
            exclusions.push(part[1..].to_string());
            continue;
        }

        let spec = parse_single_variable(part)?;
        variables.push(spec);
    }

    // Apply exclusions to all variables
    if !exclusions.is_empty() {
        for var in &mut variables {
            var.exclusions = exclusions.clone();
        }
    }

    Ok(variables)
}

/// Parse a single variable specification.
#[inline]
fn parse_single_variable(input: &str) -> Result<VariableSpec> {
    let input = input.trim();
    let bytes = input.as_bytes();

    // Check for count mode (& prefix)
    let (count_mode, input) = if bytes.first() == Some(&b'&') {
        (true, &input[1..])
    } else {
        (false, input)
    };

    // Find colon for selection (use memchr-style search)
    let colon_pos = input.bytes().position(|b| b == b':');

    let (name_str, selection) = match colon_pos {
        Some(pos) => {
            let name = &input[..pos];
            let sel_str = &input[pos + 1..];

            let selection = if sel_str.starts_with('/') && sel_str.ends_with('/') && sel_str.len() > 2 {
                Some(Selection::Regex(sel_str[1..sel_str.len() - 1].to_string()))
            } else {
                Some(Selection::Key(sel_str.to_string()))
            };

            (name, selection)
        }
        None => (input, None),
    };

    let name = VariableName::from_str(name_str).ok_or_else(|| Error::UnknownVariable {
        name: name_str.to_string(),
    })?;

    Ok(VariableSpec {
        name,
        selection,
        count_mode,
        exclusions: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_variable() {
        let vars = parse_variables("REQUEST_URI").unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].name, VariableName::RequestUri);
        assert!(vars[0].selection.is_none());
        assert!(!vars[0].count_mode);
    }

    #[test]
    fn test_parse_variable_with_selection() {
        let vars = parse_variables("ARGS:username").unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].name, VariableName::Args);
        assert!(matches!(&vars[0].selection, Some(Selection::Key(k)) if k == "username"));
    }

    #[test]
    fn test_parse_variable_with_regex() {
        let vars = parse_variables("ARGS:/^user/").unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].name, VariableName::Args);
        assert!(matches!(&vars[0].selection, Some(Selection::Regex(r)) if r == "^user"));
    }

    #[test]
    fn test_parse_count_mode() {
        let vars = parse_variables("&ARGS").unwrap();
        assert_eq!(vars.len(), 1);
        assert!(vars[0].count_mode);
    }

    #[test]
    fn test_parse_multiple_variables() {
        let vars = parse_variables("REQUEST_URI|ARGS|REQUEST_HEADERS").unwrap();
        assert_eq!(vars.len(), 3);
    }

    #[test]
    fn test_variable_lookup_case_insensitive() {
        assert_eq!(VariableName::from_str("REQUEST_URI"), Some(VariableName::RequestUri));
        assert_eq!(VariableName::from_str("request_uri"), Some(VariableName::RequestUri));
        assert_eq!(VariableName::from_str("Request_Uri"), Some(VariableName::RequestUri));
    }
}
