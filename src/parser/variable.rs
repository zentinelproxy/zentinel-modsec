//! Variable parsing for SecRule.

use crate::error::{Error, Result};

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
    /// All arguments (GET and POST).
    Args,
    /// GET arguments only.
    ArgsGet,
    /// POST arguments only.
    ArgsPost,
    /// Argument names.
    ArgsNames,
    /// GET argument names.
    ArgsGetNames,
    /// POST argument names.
    ArgsPostNames,
    /// Combined size of all arguments.
    ArgsCombinedSize,
    /// Request URI.
    RequestUri,
    /// Raw request URI.
    RequestUriRaw,
    /// Request filename.
    RequestFilename,
    /// Request basename.
    RequestBasename,
    /// Request line.
    RequestLine,
    /// HTTP method.
    RequestMethod,
    /// HTTP protocol.
    RequestProtocol,
    /// Request headers.
    RequestHeaders,
    /// Request header names.
    RequestHeadersNames,
    /// Request cookies.
    RequestCookies,
    /// Request cookie names.
    RequestCookiesNames,
    /// Request body.
    RequestBody,
    /// Request body length.
    RequestBodyLength,
    /// Query string.
    QueryString,

    // Response variables
    /// Response status code.
    ResponseStatus,
    /// Response protocol.
    ResponseProtocol,
    /// Response headers.
    ResponseHeaders,
    /// Response header names.
    ResponseHeadersNames,
    /// Response body.
    ResponseBody,
    /// Response content type.
    ResponseContentType,
    /// Response content length.
    ResponseContentLength,

    // Server/Client info
    /// Remote (client) IP address.
    RemoteAddr,
    /// Remote port.
    RemotePort,
    /// Remote hostname.
    RemoteHost,
    /// Remote user (auth).
    RemoteUser,
    /// Server IP address.
    ServerAddr,
    /// Server port.
    ServerPort,
    /// Server name.
    ServerName,

    // Collections
    /// Transaction collection (mutable).
    Tx,
    /// Session collection.
    Session,
    /// Environment variables.
    Env,
    /// IP collection.
    Ip,
    /// Global collection.
    Global,
    /// Resource collection.
    Resource,
    /// User collection.
    User,
    /// GeoIP data.
    Geo,

    // Matched data
    /// Last matched variable value.
    MatchedVar,
    /// All matched variable values.
    MatchedVars,
    /// Last matched variable name.
    MatchedVarName,
    /// All matched variable names.
    MatchedVarsNames,

    // Time variables
    /// Current time.
    Time,
    /// Current time as epoch.
    TimeEpoch,
    /// Current day.
    TimeDay,
    /// Current hour.
    TimeHour,
    /// Current minute.
    TimeMin,
    /// Current second.
    TimeSec,
    /// Time of day.
    TimeWday,
    /// Current month.
    TimeMon,
    /// Current year.
    TimeYear,

    // Files
    /// Uploaded file names.
    Files,
    /// Uploaded file sizes.
    FilesSizes,
    /// Uploaded file temp names.
    FilesTmpnames,
    /// Combined size of uploaded files.
    FilesCombinedSize,
    /// Uploaded file count.
    FilesNames,

    // Special
    /// Unique ID.
    UniqueId,
    /// Inbound anomaly score.
    InboundAnomalyScore,
    /// Outbound anomaly score.
    OutboundAnomalyScore,
    /// Duration of transaction.
    Duration,
    /// Multipart boundary.
    MultipartBoundaryQuoted,
    /// Multipart boundary whitespace.
    MultipartBoundaryWhitespace,
    /// Multipart data after.
    MultipartDataAfter,
    /// Multipart data before.
    MultipartDataBefore,
    /// Multipart file limit exceeded.
    MultipartFileLimitExceeded,
    /// Multipart header folding.
    MultipartHeaderFolding,
    /// Multipart invalid header folding.
    MultipartInvalidHeaderFolding,
    /// Multipart invalid part.
    MultipartInvalidPart,
    /// Multipart invalid quoting.
    MultipartInvalidQuoting,
    /// Multipart LF line.
    MultipartLfLine,
    /// Multipart missing semicolon.
    MultipartMissingSemicolon,
    /// Multipart strict error.
    MultipartStrictError,
    /// Multipart unmatched boundary.
    MultipartUnmatchedBoundary,

    // XML
    /// XML data.
    Xml,

    // Web server
    /// Web server error log.
    WebserverErrorLog,
    /// Highest severity.
    HighestSeverity,
    /// Status line.
    StatusLine,
    /// Full request.
    FullRequest,
    /// Full request length.
    FullRequestLength,

    // Auth
    /// Auth type.
    AuthType,
}

impl VariableName {
    /// Parse a variable name from a string.
    pub fn from_str(s: &str) -> Option<Self> {
        let upper = s.to_uppercase();
        match upper.as_str() {
            "ARGS" => Some(Self::Args),
            "ARGS_GET" => Some(Self::ArgsGet),
            "ARGS_POST" => Some(Self::ArgsPost),
            "ARGS_NAMES" => Some(Self::ArgsNames),
            "ARGS_GET_NAMES" => Some(Self::ArgsGetNames),
            "ARGS_POST_NAMES" => Some(Self::ArgsPostNames),
            "ARGS_COMBINED_SIZE" => Some(Self::ArgsCombinedSize),
            "REQUEST_URI" => Some(Self::RequestUri),
            "REQUEST_URI_RAW" => Some(Self::RequestUriRaw),
            "REQUEST_FILENAME" => Some(Self::RequestFilename),
            "REQUEST_BASENAME" => Some(Self::RequestBasename),
            "REQUEST_LINE" => Some(Self::RequestLine),
            "REQUEST_METHOD" => Some(Self::RequestMethod),
            "REQUEST_PROTOCOL" => Some(Self::RequestProtocol),
            "REQUEST_HEADERS" => Some(Self::RequestHeaders),
            "REQUEST_HEADERS_NAMES" => Some(Self::RequestHeadersNames),
            "REQUEST_COOKIES" => Some(Self::RequestCookies),
            "REQUEST_COOKIES_NAMES" => Some(Self::RequestCookiesNames),
            "REQUEST_BODY" => Some(Self::RequestBody),
            "REQUEST_BODY_LENGTH" => Some(Self::RequestBodyLength),
            "QUERY_STRING" => Some(Self::QueryString),
            "RESPONSE_STATUS" => Some(Self::ResponseStatus),
            "RESPONSE_PROTOCOL" => Some(Self::ResponseProtocol),
            "RESPONSE_HEADERS" => Some(Self::ResponseHeaders),
            "RESPONSE_HEADERS_NAMES" => Some(Self::ResponseHeadersNames),
            "RESPONSE_BODY" => Some(Self::ResponseBody),
            "RESPONSE_CONTENT_TYPE" => Some(Self::ResponseContentType),
            "RESPONSE_CONTENT_LENGTH" => Some(Self::ResponseContentLength),
            "REMOTE_ADDR" => Some(Self::RemoteAddr),
            "REMOTE_PORT" => Some(Self::RemotePort),
            "REMOTE_HOST" => Some(Self::RemoteHost),
            "REMOTE_USER" => Some(Self::RemoteUser),
            "SERVER_ADDR" => Some(Self::ServerAddr),
            "SERVER_PORT" => Some(Self::ServerPort),
            "SERVER_NAME" => Some(Self::ServerName),
            "TX" => Some(Self::Tx),
            "SESSION" => Some(Self::Session),
            "ENV" => Some(Self::Env),
            "IP" => Some(Self::Ip),
            "GLOBAL" => Some(Self::Global),
            "RESOURCE" => Some(Self::Resource),
            "USER" => Some(Self::User),
            "GEO" => Some(Self::Geo),
            "MATCHED_VAR" => Some(Self::MatchedVar),
            "MATCHED_VARS" => Some(Self::MatchedVars),
            "MATCHED_VAR_NAME" => Some(Self::MatchedVarName),
            "MATCHED_VARS_NAMES" => Some(Self::MatchedVarsNames),
            "TIME" => Some(Self::Time),
            "TIME_EPOCH" => Some(Self::TimeEpoch),
            "TIME_DAY" => Some(Self::TimeDay),
            "TIME_HOUR" => Some(Self::TimeHour),
            "TIME_MIN" => Some(Self::TimeMin),
            "TIME_SEC" => Some(Self::TimeSec),
            "TIME_WDAY" => Some(Self::TimeWday),
            "TIME_MON" => Some(Self::TimeMon),
            "TIME_YEAR" => Some(Self::TimeYear),
            "FILES" => Some(Self::Files),
            "FILES_SIZES" => Some(Self::FilesSizes),
            "FILES_TMPNAMES" => Some(Self::FilesTmpnames),
            "FILES_COMBINED_SIZE" => Some(Self::FilesCombinedSize),
            "FILES_NAMES" => Some(Self::FilesNames),
            "UNIQUE_ID" => Some(Self::UniqueId),
            "DURATION" => Some(Self::Duration),
            "HIGHEST_SEVERITY" => Some(Self::HighestSeverity),
            "STATUS_LINE" => Some(Self::StatusLine),
            "FULL_REQUEST" => Some(Self::FullRequest),
            "FULL_REQUEST_LENGTH" => Some(Self::FullRequestLength),
            "AUTH_TYPE" => Some(Self::AuthType),
            "XML" => Some(Self::Xml),
            _ => None,
        }
    }

    /// Check if this variable is a collection.
    pub fn is_collection(&self) -> bool {
        matches!(
            self,
            Self::Args
                | Self::ArgsGet
                | Self::ArgsPost
                | Self::ArgsNames
                | Self::RequestHeaders
                | Self::RequestHeadersNames
                | Self::RequestCookies
                | Self::RequestCookiesNames
                | Self::ResponseHeaders
                | Self::ResponseHeadersNames
                | Self::Tx
                | Self::Session
                | Self::Env
                | Self::Ip
                | Self::Global
                | Self::Resource
                | Self::User
                | Self::Geo
                | Self::MatchedVars
                | Self::MatchedVarsNames
                | Self::Files
                | Self::FilesSizes
                | Self::FilesTmpnames
                | Self::FilesNames
        )
    }
}

/// Parse a variable specification string.
pub fn parse_variables(input: &str) -> Result<Vec<VariableSpec>> {
    let mut variables = Vec::new();
    let mut exclusions: Vec<String> = Vec::new();

    // Split by | for OR conditions (we collect all)
    for part in input.split('|') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // Handle exclusions (!VAR)
        if part.starts_with('!') {
            let excl = &part[1..];
            exclusions.push(excl.to_string());
            continue;
        }

        let spec = parse_single_variable(part)?;
        variables.push(spec);
    }

    // Apply exclusions to all variables
    for var in &mut variables {
        var.exclusions = exclusions.clone();
    }

    Ok(variables)
}

/// Parse a single variable specification.
fn parse_single_variable(input: &str) -> Result<VariableSpec> {
    let input = input.trim();

    // Check for count mode (& prefix)
    let (count_mode, input) = if input.starts_with('&') {
        (true, &input[1..])
    } else {
        (false, input)
    };

    // Split name and selection (VAR:selection or VAR:/regex/)
    let (name_str, selection) = if let Some(pos) = input.find(':') {
        let name = &input[..pos];
        let sel_str = &input[pos + 1..];

        let selection = if sel_str.starts_with('/') && sel_str.ends_with('/') {
            // Regex selection
            let pattern = &sel_str[1..sel_str.len() - 1];
            Some(Selection::Regex(pattern.to_string()))
        } else {
            // Static key selection
            Some(Selection::Key(sel_str.to_string()))
        };

        (name, selection)
    } else {
        (input, None)
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
}
