//! Transformation functions for ModSecurity.

mod decode;
mod encode;
mod normalize;
mod pipeline;

pub use decode::*;
pub use encode::*;
pub use normalize::*;
pub use pipeline::TransformationPipeline;

use crate::error::{Error, Result};
use std::borrow::Cow;
use std::sync::Arc;

/// Trait for transformations.
pub trait Transformation: Send + Sync {
    /// Apply the transformation.
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str>;

    /// Get the transformation name.
    fn name(&self) -> &'static str;
}

/// Create a transformation from a name.
pub fn create_transformation(name: &str) -> Result<Arc<dyn Transformation>> {
    match name.to_lowercase().as_str() {
        // Decoding
        "urldecode" => Ok(Arc::new(UrlDecode)),
        "urldecodeuni" => Ok(Arc::new(UrlDecodeUni)),
        "base64decode" => Ok(Arc::new(Base64Decode)),
        "base64decodeext" => Ok(Arc::new(Base64DecodeExt)),
        "hexdecode" => Ok(Arc::new(HexDecode)),
        "htmlentitydecode" => Ok(Arc::new(HtmlEntityDecode)),
        "jsdecode" => Ok(Arc::new(JsDecode)),
        "cssdecode" => Ok(Arc::new(CssDecode)),

        // Encoding
        "base64encode" => Ok(Arc::new(Base64Encode)),
        "hexencode" => Ok(Arc::new(HexEncode)),
        "urlencode" => Ok(Arc::new(UrlEncode)),

        // Normalization
        "lowercase" => Ok(Arc::new(Lowercase)),
        "uppercase" => Ok(Arc::new(Uppercase)),
        "compresswhitespace" => Ok(Arc::new(CompressWhitespace)),
        "removewhitespace" => Ok(Arc::new(RemoveWhitespace)),
        "removenulls" => Ok(Arc::new(RemoveNulls)),
        "replacenulls" => Ok(Arc::new(ReplaceNulls)),
        "trim" => Ok(Arc::new(Trim)),
        "trimleft" => Ok(Arc::new(TrimLeft)),
        "trimright" => Ok(Arc::new(TrimRight)),
        "normalizepath" => Ok(Arc::new(NormalizePath)),
        "normalizepathwin" => Ok(Arc::new(NormalizePathWin)),
        "removecomments" => Ok(Arc::new(RemoveComments)),
        "cmdline" => Ok(Arc::new(CmdLine)),

        // Hashing
        "md5" => Ok(Arc::new(Md5)),
        "sha1" => Ok(Arc::new(Sha1)),

        // Special
        "length" => Ok(Arc::new(Length)),
        "none" => Ok(Arc::new(None_)),

        _ => Err(Error::UnknownTransformation { name: name.to_string() }),
    }
}

/// None transformation (clears the transformation chain).
pub struct None_;

impl Transformation for None_ {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        Cow::Borrowed(input)
    }

    fn name(&self) -> &'static str {
        "none"
    }
}

/// Length transformation (returns the length of the input).
pub struct Length;

impl Transformation for Length {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        Cow::Owned(input.len().to_string())
    }

    fn name(&self) -> &'static str {
        "length"
    }
}
