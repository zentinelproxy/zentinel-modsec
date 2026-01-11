//! XSS (Cross-Site Scripting) detection.
//!
//! This module detects XSS attacks by analyzing input for dangerous
//! HTML tags, JavaScript event handlers, and other attack vectors.
//!
//! Optimized for performance using:
//! - RegexSet for fast multi-pattern matching
//! - Aho-Corasick for event handler detection
//! - Lazy static compilation of all patterns

use super::DetectionResult;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use once_cell::sync::Lazy;
use regex::{RegexSet, Regex};

// ============================================================================
// Static Pattern Matchers (compiled once at first use)
// ============================================================================

/// RegexSet for fast multi-pattern XSS detection.
/// All patterns checked in a single pass.
static XSS_REGEX_SET: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new([
        // Script tags
        r"(?i)<script[^>]*>",
        r"(?i)</script>",
        // Event handlers in attributes (generic)
        r"(?i)\bon\w+\s*=",
        // JavaScript URLs
        r"(?i)javascript\s*:",
        // Data URLs with HTML/script content
        r"(?i)data\s*:\s*text/html",
        // VBScript URLs
        r"(?i)vbscript\s*:",
        // Expression in CSS (IE)
        r"(?i)expression\s*\(",
        // Behavior in CSS
        r"(?i)behavior\s*:",
        // -moz-binding in CSS
        r"(?i)-moz-binding\s*:",
        // URL with JavaScript in CSS
        r#"(?i)url\s*\(\s*["']?\s*javascript"#,
        // @import in CSS
        r"(?i)@import",
        // Iframe tags
        r"(?i)<iframe",
        // Object/Embed/Applet tags
        r"(?i)<(?:object|embed|applet)",
        // Form with JavaScript action
        r#"(?i)<form[^>]*action\s*=\s*["']?\s*javascript"#,
        // Link with JavaScript href
        r#"(?i)<a[^>]*href\s*=\s*["']?\s*javascript"#,
        // Meta refresh
        r#"(?i)<meta[^>]*http-equiv\s*=\s*["']?refresh"#,
        // Base tag
        r"(?i)<base[^>]*href",
        // FSCommand (Flash)
        r"(?i)fscommand",
        // eval()
        r"(?i)\beval\s*\(",
        // setTimeout/setInterval with string
        r#"(?i)(?:setTimeout|setInterval)\s*\(\s*["']"#,
        // document.write
        r"(?i)document\s*\.\s*write",
        // innerHTML/outerHTML assignment
        r"(?i)\.(?:innerHTML|outerHTML)\s*=",
        // document.location
        r"(?i)document\s*\.\s*location",
        // window.location
        r"(?i)window\s*\.\s*location",
        // document.cookie
        r"(?i)document\s*\.\s*cookie",
    ]).expect("XSS regex patterns should compile")
});

/// Aho-Corasick matcher for dangerous HTML tags.
/// Uses leftmost-first matching for speed.
static DANGEROUS_TAGS_AC: Lazy<AhoCorasick> = Lazy::new(|| {
    let tags = [
        "<script", "<iframe", "<object", "<embed", "<applet", "<form",
        "<input", "<button", "<select", "<textarea", "<link", "<style",
        "<meta", "<base", "<svg", "<math", "<video", "<audio", "<source",
        "<track", "<canvas", "<frame", "<frameset", "<layer", "<ilayer",
        "<bgsound", "<isindex", "<marquee", "<blink", "<plaintext",
        "<listing", "<xmp", "<noscript", "<template", "<slot", "<portal",
        "<img", "<body",
    ];
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(&tags)
        .expect("Dangerous tags AC should build")
});

/// Aho-Corasick matcher for event handlers.
static EVENT_HANDLERS_AC: Lazy<AhoCorasick> = Lazy::new(|| {
    let handlers = [
        "onabort=", "onafterprint=", "onanimationend=", "onanimationiteration=",
        "onanimationstart=", "onbeforeprint=", "onbeforeunload=", "onblur=",
        "oncanplay=", "oncanplaythrough=", "onchange=", "onclick=", "oncontextmenu=",
        "oncopy=", "oncut=", "ondblclick=", "ondrag=", "ondragend=", "ondragenter=",
        "ondragleave=", "ondragover=", "ondragstart=", "ondrop=", "ondurationchange=",
        "onemptied=", "onended=", "onerror=", "onfocus=", "onfocusin=", "onfocusout=",
        "onhashchange=", "oninput=", "oninvalid=", "onkeydown=", "onkeypress=",
        "onkeyup=", "onload=", "onloadeddata=", "onloadedmetadata=", "onloadstart=",
        "onmessage=", "onmousedown=", "onmouseenter=", "onmouseleave=", "onmousemove=",
        "onmouseout=", "onmouseover=", "onmouseup=", "onmousewheel=", "onoffline=",
        "ononline=", "onopen=", "onpagehide=", "onpageshow=", "onpaste=", "onpause=",
        "onplay=", "onplaying=", "onpopstate=", "onprogress=", "onratechange=",
        "onreset=", "onresize=", "onscroll=", "onsearch=", "onseeked=", "onseeking=",
        "onselect=", "onshow=", "onstalled=", "onstorage=", "onsubmit=", "onsuspend=",
        "ontimeupdate=", "ontoggle=", "ontouchcancel=", "ontouchend=", "ontouchmove=",
        "ontouchstart=", "ontransitionend=", "onunload=", "onvolumechange=",
        "onwaiting=", "onwheel=", "onpointerdown=", "onpointermove=", "onpointerup=",
        "onpointercancel=", "onpointerenter=", "onpointerleave=", "onpointerover=",
        "onpointerout=", "ongotpointercapture=", "onlostpointercapture=",
        "onbeforeinput=", "onformdata=", "onsecuritypolicyviolation=",
        "onslotchange=", "onvisibilitychange=",
    ];
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(&handlers)
        .expect("Event handlers AC should build")
});

/// Aho-Corasick matcher for dangerous URL schemes.
static DANGEROUS_SCHEMES_AC: Lazy<AhoCorasick> = Lazy::new(|| {
    let schemes = ["javascript:", "vbscript:", "livescript:", "mocha:"];
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(&schemes)
        .expect("Dangerous schemes AC should build")
});

/// Quick-check patterns using Aho-Corasick for fast rejection.
static QUICK_CHECK_AC: Lazy<AhoCorasick> = Lazy::new(|| {
    let patterns = [
        "<", "javascript", "vbscript", "on", "eval", "innerhtml", "outerhtml",
        "document.", "window.", "%3c", "&lt", "\\x3c", "\\u003c",
    ];
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(&patterns)
        .expect("Quick check AC should build")
});

/// Regex for normalizing whitespace in tags (compiled once).
static NORMALIZE_TAG_WS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"<\s+").expect("Tag whitespace regex should compile")
});

/// Regex for normalizing attribute spacing (compiled once).
static NORMALIZE_ATTR_WS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\s*=\s*").expect("Attribute whitespace regex should compile")
});

// ============================================================================
// Public API
// ============================================================================

/// Check if the input contains XSS.
#[inline]
pub fn is_xss(input: &str) -> bool {
    detect_xss(input).is_injection
}

/// Detect XSS in input.
pub fn detect_xss(input: &str) -> DetectionResult {
    // Fast path: quick check for any potential XSS indicators
    if !QUICK_CHECK_AC.is_match(input) {
        return DetectionResult::safe();
    }

    // Check raw input first (fastest path for obvious attacks)
    if let Some(result) = check_patterns(input) {
        return result;
    }

    // Only normalize if we haven't found anything yet
    // This is the slow path for encoded attacks
    let normalized = normalize_input(input);
    if normalized != input {
        if let Some(result) = check_patterns(&normalized) {
            return result;
        }
    }

    DetectionResult::safe()
}

// ============================================================================
// Internal Functions
// ============================================================================

/// Check all XSS patterns against input.
#[inline]
fn check_patterns(input: &str) -> Option<DetectionResult> {
    // RegexSet check - single pass through all patterns
    if XSS_REGEX_SET.is_match(input) {
        return Some(DetectionResult::detected("XSS pattern match".to_string()));
    }

    // Aho-Corasick checks - very fast O(n) scans
    if DANGEROUS_TAGS_AC.is_match(input) {
        return Some(DetectionResult::detected("Dangerous HTML tag".to_string()));
    }

    if EVENT_HANDLERS_AC.is_match(input) {
        return Some(DetectionResult::detected("Event handler".to_string()));
    }

    if DANGEROUS_SCHEMES_AC.is_match(input) {
        return Some(DetectionResult::detected("Dangerous URL scheme".to_string()));
    }

    None
}

/// Normalize input by decoding common encodings.
/// Only called when the fast path doesn't match.
fn normalize_input(input: &str) -> String {
    let mut result = input.to_string();

    // Decode HTML entities
    let decoded = html_escape::decode_html_entities(&result);
    if decoded != result {
        result = decoded.into_owned();
    }

    // Decode URL encoding
    if let Ok(decoded) = percent_encoding::percent_decode_str(&result).decode_utf8() {
        if decoded != result {
            result = decoded.into_owned();
        }
    }

    // Remove null bytes (used for filter evasion)
    if result.contains('\0') {
        result = result.replace('\0', "");
    }

    // Normalize whitespace in tags: "< script" -> "<script"
    if result.contains("< ") {
        result = NORMALIZE_TAG_WS.replace_all(&result, "<").into_owned();
    }

    // Normalize attribute spacing: "on click = " -> "onclick="
    if result.contains(" =") || result.contains("= ") {
        result = NORMALIZE_ATTR_WS.replace_all(&result, "=").into_owned();
    }

    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_tag() {
        assert!(is_xss("<script>alert(1)</script>"));
        assert!(is_xss("<SCRIPT>alert(1)</SCRIPT>"));
        assert!(is_xss("<script src=evil.js>"));
        assert!(is_xss("<script/src=evil.js>"));
    }

    #[test]
    fn test_event_handlers() {
        assert!(is_xss("<img src=x onerror=alert(1)>"));
        assert!(is_xss("<body onload=alert(1)>"));
        assert!(is_xss("<svg onload=alert(1)>"));
        assert!(is_xss("<input onfocus=alert(1) autofocus>"));
    }

    #[test]
    fn test_javascript_url() {
        assert!(is_xss("<a href=javascript:alert(1)>click</a>"));
        assert!(is_xss("<a href=\"javascript:alert(1)\">click</a>"));
        assert!(is_xss("javascript:alert(document.cookie)"));
    }

    #[test]
    fn test_encoded_xss() {
        // URL encoded
        assert!(is_xss("%3Cscript%3Ealert(1)%3C/script%3E"));
        // HTML entity encoded
        assert!(is_xss("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn test_svg_xss() {
        assert!(is_xss("<svg onload=alert(1)>"));
        assert!(is_xss("<svg><script>alert(1)</script></svg>"));
    }

    #[test]
    fn test_iframe() {
        assert!(is_xss("<iframe src=javascript:alert(1)>"));
        assert!(is_xss("<iframe src=\"evil.com\">"));
    }

    #[test]
    fn test_safe_input() {
        assert!(!is_xss("hello world"));
        assert!(!is_xss("This is normal text without any special characters"));
        assert!(!is_xss("12345"));
        assert!(!is_xss("user@example.com"));
    }

    #[test]
    fn test_dom_xss() {
        assert!(is_xss("document.write('<script>')"));
        assert!(is_xss("element.innerHTML = userInput"));
        assert!(is_xss("eval('malicious code')"));
    }

    #[test]
    fn test_quick_reject() {
        // These should be quickly rejected without normalization
        assert!(!is_xss("hello world"));
        assert!(!is_xss("just some text"));
        assert!(!is_xss("numbers 12345"));
    }
}
