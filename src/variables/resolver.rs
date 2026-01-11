//! Variable resolution engine.

use super::{RequestData, ResponseData, TxCollection};
use crate::parser::{Selection, VariableName, VariableSpec};
use regex::Regex;

/// Variable resolver for transaction context.
pub struct VariableResolver<'a> {
    request: &'a RequestData,
    response: &'a ResponseData,
    tx: &'a TxCollection,
    matched_var: Option<&'a str>,
    matched_vars: &'a [(String, String)],
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

    /// Resolve a variable specification to values.
    pub fn resolve(&self, spec: &VariableSpec) -> Vec<(String, String)> {
        let values = self.resolve_variable(spec.name, &spec.selection);

        // Apply exclusions
        if spec.exclusions.is_empty() {
            values
        } else {
            values
                .into_iter()
                .filter(|(k, _)| !spec.exclusions.iter().any(|e| k.contains(e)))
                .collect()
        }
    }

    /// Resolve a variable by name.
    fn resolve_variable(
        &self,
        name: VariableName,
        selection: &Option<Selection>,
    ) -> Vec<(String, String)> {
        match name {
            // Request variables
            VariableName::RequestUri => {
                vec![("REQUEST_URI".to_string(), self.request.uri.clone())]
            }
            VariableName::RequestUriRaw => {
                vec![("REQUEST_URI_RAW".to_string(), self.request.uri_raw.clone())]
            }
            VariableName::RequestMethod => {
                vec![("REQUEST_METHOD".to_string(), self.request.method.clone())]
            }
            VariableName::RequestProtocol => {
                vec![(
                    "REQUEST_PROTOCOL".to_string(),
                    self.request.protocol.clone(),
                )]
            }
            VariableName::QueryString => {
                vec![(
                    "QUERY_STRING".to_string(),
                    self.request.query_string.clone(),
                )]
            }
            VariableName::RequestFilename => {
                vec![("REQUEST_FILENAME".to_string(), self.request.path.clone())]
            }
            VariableName::RequestBody => {
                vec![("REQUEST_BODY".to_string(), self.request.body_str())]
            }
            VariableName::RequestBodyLength => {
                vec![(
                    "REQUEST_BODY_LENGTH".to_string(),
                    self.request.body_length().to_string(),
                )]
            }

            // Collections
            VariableName::Args => self.resolve_collection_from_all_args(selection),
            VariableName::ArgsGet => {
                self.resolve_collection(&self.request.args_get, "ARGS_GET", selection)
            }
            VariableName::ArgsPost => {
                self.resolve_collection(&self.request.args_post, "ARGS_POST", selection)
            }
            VariableName::RequestHeaders => {
                self.resolve_collection(&self.request.headers, "REQUEST_HEADERS", selection)
            }
            VariableName::RequestCookies => {
                self.resolve_collection(&self.request.cookies, "REQUEST_COOKIES", selection)
            }

            // Response variables
            VariableName::ResponseStatus => {
                vec![(
                    "RESPONSE_STATUS".to_string(),
                    self.response.status.to_string(),
                )]
            }
            VariableName::ResponseBody => {
                vec![("RESPONSE_BODY".to_string(), self.response.body_str())]
            }
            VariableName::ResponseContentType => {
                vec![(
                    "RESPONSE_CONTENT_TYPE".to_string(),
                    self.response.content_type.clone(),
                )]
            }
            VariableName::ResponseHeaders => {
                self.resolve_collection(&self.response.headers, "RESPONSE_HEADERS", selection)
            }

            // TX collection
            VariableName::Tx => self.resolve_tx_collection(selection),

            // Client/Server info
            VariableName::RemoteAddr => {
                vec![("REMOTE_ADDR".to_string(), self.request.client_ip.clone())]
            }
            VariableName::RemotePort => {
                vec![(
                    "REMOTE_PORT".to_string(),
                    self.request.client_port.to_string(),
                )]
            }
            VariableName::ServerName => {
                vec![("SERVER_NAME".to_string(), self.request.server_name.clone())]
            }
            VariableName::ServerPort => {
                vec![(
                    "SERVER_PORT".to_string(),
                    self.request.server_port.to_string(),
                )]
            }

            // Matched variables
            VariableName::MatchedVar => {
                if let Some(v) = self.matched_var {
                    vec![("MATCHED_VAR".to_string(), v.to_string())]
                } else {
                    vec![]
                }
            }
            VariableName::MatchedVars => self
                .matched_vars
                .iter()
                .map(|(k, v)| (format!("MATCHED_VARS:{}", k), v.clone()))
                .collect(),

            // Default - empty
            _ => vec![],
        }
    }

    /// Resolve a collection with optional selection.
    fn resolve_collection(
        &self,
        collection: &super::collection::HashMapCollection,
        prefix: &str,
        selection: &Option<Selection>,
    ) -> Vec<(String, String)> {
        use super::collection::Collection;

        match selection {
            Some(Selection::Key(key)) => {
                if let Some(values) = collection.get(key) {
                    values
                        .into_iter()
                        .map(|v| (format!("{}:{}", prefix, key), v.to_string()))
                        .collect()
                } else {
                    vec![]
                }
            }
            Some(Selection::Regex(pattern)) => {
                if let Ok(re) = Regex::new(pattern) {
                    collection
                        .get_regex(&re)
                        .into_iter()
                        .map(|(k, v)| (format!("{}:{}", prefix, k), v.to_string()))
                        .collect()
                } else {
                    vec![]
                }
            }
            None => collection
                .all()
                .into_iter()
                .map(|(k, v)| (format!("{}:{}", prefix, k), v.to_string()))
                .collect(),
        }
    }

    /// Resolve ARGS collection (GET + POST combined).
    fn resolve_collection_from_all_args(&self, selection: &Option<Selection>) -> Vec<(String, String)> {
        let mut result = self.resolve_collection(&self.request.args_get, "ARGS", selection);
        result.extend(self.resolve_collection(&self.request.args_post, "ARGS", selection));
        result
    }

    /// Resolve TX collection.
    fn resolve_tx_collection(&self, selection: &Option<Selection>) -> Vec<(String, String)> {
        use super::collection::Collection;

        match selection {
            Some(Selection::Key(key)) => {
                if let Some(values) = self.tx.get(key) {
                    values
                        .into_iter()
                        .map(|v| (format!("TX:{}", key), v.to_string()))
                        .collect()
                } else {
                    vec![]
                }
            }
            Some(Selection::Regex(pattern)) => {
                if let Ok(re) = Regex::new(pattern) {
                    self.tx
                        .get_regex(&re)
                        .into_iter()
                        .map(|(k, v)| (format!("TX:{}", k), v.to_string()))
                        .collect()
                } else {
                    vec![]
                }
            }
            None => self
                .tx
                .all()
                .into_iter()
                .map(|(k, v)| (format!("TX:{}", k), v.to_string()))
                .collect(),
        }
    }
}
