//! XSS (Cross-Site Scripting) detection.
//!
//! This module detects XSS attacks by analyzing input for dangerous
//! HTML tags, JavaScript event handlers, and other attack vectors.

use super::DetectionResult;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

/// Dangerous HTML tags that can execute JavaScript.
static DANGEROUS_TAGS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "script", "iframe", "object", "embed", "applet", "form", "input",
        "button", "select", "textarea", "link", "style", "meta", "base",
        "svg", "math", "video", "audio", "source", "track", "canvas",
        "frame", "frameset", "layer", "ilayer", "bgsound", "isindex",
        "marquee", "blink", "plaintext", "listing", "xmp", "noscript",
        "template", "slot", "portal",
    ]
    .iter()
    .cloned()
    .collect()
});

/// JavaScript event handlers.
static EVENT_HANDLERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "onabort", "onafterprint", "onanimationend", "onanimationiteration",
        "onanimationstart", "onbeforeprint", "onbeforeunload", "onblur",
        "oncanplay", "oncanplaythrough", "onchange", "onclick", "oncontextmenu",
        "oncopy", "oncut", "ondblclick", "ondrag", "ondragend", "ondragenter",
        "ondragleave", "ondragover", "ondragstart", "ondrop", "ondurationchange",
        "onemptied", "onended", "onerror", "onfocus", "onfocusin", "onfocusout",
        "onhashchange", "oninput", "oninvalid", "onkeydown", "onkeypress",
        "onkeyup", "onload", "onloadeddata", "onloadedmetadata", "onloadstart",
        "onmessage", "onmousedown", "onmouseenter", "onmouseleave", "onmousemove",
        "onmouseout", "onmouseover", "onmouseup", "onmousewheel", "onoffline",
        "ononline", "onopen", "onpagehide", "onpageshow", "onpaste", "onpause",
        "onplay", "onplaying", "onpopstate", "onprogress", "onratechange",
        "onreset", "onresize", "onscroll", "onsearch", "onseeked", "onseeking",
        "onselect", "onshow", "onstalled", "onstorage", "onsubmit", "onsuspend",
        "ontimeupdate", "ontoggle", "ontouchcancel", "ontouchend", "ontouchmove",
        "ontouchstart", "ontransitionend", "onunload", "onvolumechange",
        "onwaiting", "onwheel", "onpointerdown", "onpointermove", "onpointerup",
        "onpointercancel", "onpointerenter", "onpointerleave", "onpointerover",
        "onpointerout", "ongotpointercapture", "onlostpointercapture",
        "onbeforeinput", "onformdata", "onratechange", "onsecuritypolicyviolation",
        "onslotchange", "onvisibilitychange",
    ]
    .iter()
    .cloned()
    .collect()
});

/// Dangerous URL schemes.
static DANGEROUS_SCHEMES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    ["javascript", "vbscript", "data", "livescript", "mocha"]
        .iter()
        .cloned()
        .collect()
});

/// Regex patterns for XSS detection.
static XSS_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Script tags
        Regex::new(r"(?i)<script[^>]*>").unwrap(),
        Regex::new(r"(?i)</script>").unwrap(),
        // Event handlers in attributes
        Regex::new(r"(?i)\bon\w+\s*=").unwrap(),
        // JavaScript URLs
        Regex::new(r"(?i)javascript\s*:").unwrap(),
        // Data URLs with JavaScript
        Regex::new(r"(?i)data\s*:\s*text/html").unwrap(),
        // VBScript URLs
        Regex::new(r"(?i)vbscript\s*:").unwrap(),
        // Expression in CSS
        Regex::new(r"(?i)expression\s*\(").unwrap(),
        // Behavior in CSS
        Regex::new(r"(?i)behavior\s*:").unwrap(),
        // Binding in CSS
        Regex::new(r"(?i)-moz-binding\s*:").unwrap(),
        // URL() in CSS
        Regex::new(r#"(?i)url\s*\(\s*["']?\s*javascript"#).unwrap(),
        // Import in CSS
        Regex::new(r"(?i)@import").unwrap(),
        // SVG event handlers
        Regex::new(r"(?i)<svg[^>]*on\w+\s*=").unwrap(),
        // IMG onerror
        Regex::new(r"(?i)<img[^>]*onerror\s*=").unwrap(),
        // Body onload
        Regex::new(r"(?i)<body[^>]*onload\s*=").unwrap(),
        // Iframe
        Regex::new(r"(?i)<iframe").unwrap(),
        // Object/Embed
        Regex::new(r"(?i)<(object|embed|applet)").unwrap(),
        // Form action JavaScript
        Regex::new(r#"(?i)<form[^>]*action\s*=\s*["']?\s*javascript"#).unwrap(),
        // Input with event handlers
        Regex::new(r"(?i)<input[^>]*on\w+\s*=").unwrap(),
        // Link with JavaScript
        Regex::new(r#"(?i)<a[^>]*href\s*=\s*["']?\s*javascript"#).unwrap(),
        // Meta refresh with JavaScript
        Regex::new(r#"(?i)<meta[^>]*http-equiv\s*=\s*["']?refresh"#).unwrap(),
        // Base tag
        Regex::new(r"(?i)<base[^>]*href").unwrap(),
        // FSCommand
        Regex::new(r"(?i)fscommand").unwrap(),
        // Eval
        Regex::new(r"(?i)\beval\s*\(").unwrap(),
        // SetTimeout/SetInterval with string
        Regex::new(r#"(?i)(setTimeout|setInterval)\s*\(\s*["']"#).unwrap(),
        // document.write
        Regex::new(r"(?i)document\s*\.\s*write").unwrap(),
        // innerHTML
        Regex::new(r"(?i)\.innerHTML\s*=").unwrap(),
        // outerHTML
        Regex::new(r"(?i)\.outerHTML\s*=").unwrap(),
        // document.location
        Regex::new(r"(?i)document\s*\.\s*location").unwrap(),
        // window.location
        Regex::new(r"(?i)window\s*\.\s*location").unwrap(),
        // document.cookie
        Regex::new(r"(?i)document\s*\.\s*cookie").unwrap(),
    ]
});

/// Check if the input contains XSS.
pub fn is_xss(input: &str) -> bool {
    let result = detect_xss(input);
    result.is_injection
}

/// Detect XSS in input.
pub fn detect_xss(input: &str) -> DetectionResult {
    let lower = input.to_lowercase();

    // Quick check for potential XSS indicators (including encoded patterns)
    let has_potential_xss = lower.contains('<')
        || lower.contains("javascript")
        || lower.contains("on")
        || lower.contains("eval")
        || lower.contains("innerhtml")
        || lower.contains("outerhtml")
        || lower.contains("document.")
        || lower.contains("window.")
        || lower.contains("%3c")  // URL-encoded <
        || lower.contains("&lt")  // HTML-encoded <
        || lower.contains("\\x3c") // Hex-encoded <
        || lower.contains("\\u003c"); // Unicode-encoded <

    if !has_potential_xss {
        return DetectionResult::safe();
    }

    // Normalize input (decode common encodings)
    let normalized = normalize_input(input);

    // Check regex patterns
    for pattern in XSS_PATTERNS.iter() {
        if pattern.is_match(&normalized) {
            return DetectionResult::detected(format!("Pattern: {}", pattern.as_str()));
        }
    }

    // Check for dangerous tags
    if let Some(tag) = find_dangerous_tag(&normalized) {
        return DetectionResult::detected(format!("Dangerous tag: {}", tag));
    }

    // Check for event handlers
    if let Some(handler) = find_event_handler(&normalized) {
        return DetectionResult::detected(format!("Event handler: {}", handler));
    }

    // Check for dangerous URL schemes
    if let Some(scheme) = find_dangerous_scheme(&normalized) {
        return DetectionResult::detected(format!("Dangerous scheme: {}", scheme));
    }

    DetectionResult::safe()
}

/// Normalize input by decoding common encodings.
fn normalize_input(input: &str) -> String {
    let mut result = input.to_string();

    // Decode HTML entities
    result = html_escape::decode_html_entities(&result).into_owned();

    // Decode URL encoding
    if let Ok(decoded) = percent_encoding::percent_decode_str(&result).decode_utf8() {
        result = decoded.into_owned();
    }

    // Remove null bytes
    result = result.replace('\0', "");

    // Normalize whitespace in tags
    let ws_re = Regex::new(r"<\s*(\w+)").unwrap();
    result = ws_re.replace_all(&result, "<$1").into_owned();

    // Normalize attribute spacing
    let attr_re = Regex::new(r"\s*=\s*").unwrap();
    result = attr_re.replace_all(&result, "=").into_owned();

    result
}

/// Find dangerous HTML tags.
fn find_dangerous_tag(input: &str) -> Option<String> {
    let lower = input.to_lowercase();
    let tag_re = Regex::new(r"<\s*/?(\w+)").unwrap();

    for cap in tag_re.captures_iter(&lower) {
        if let Some(tag) = cap.get(1) {
            let tag_name = tag.as_str();
            if DANGEROUS_TAGS.contains(tag_name) {
                return Some(tag_name.to_string());
            }
        }
    }

    None
}

/// Find event handlers in attributes.
fn find_event_handler(input: &str) -> Option<String> {
    let lower = input.to_lowercase();

    for handler in EVENT_HANDLERS.iter() {
        if lower.contains(&format!("{}=", handler)) || lower.contains(&format!("{} =", handler)) {
            return Some(handler.to_string());
        }
    }

    None
}

/// Find dangerous URL schemes.
fn find_dangerous_scheme(input: &str) -> Option<String> {
    let lower = input.to_lowercase();

    for scheme in DANGEROUS_SCHEMES.iter() {
        if lower.contains(&format!("{}:", scheme)) {
            return Some(scheme.to_string());
        }
    }

    None
}

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
        assert!(!is_xss("<p>Normal paragraph</p>"));
        assert!(!is_xss("<b>Bold text</b>"));
        assert!(!is_xss("<i>Italic</i>"));
    }

    #[test]
    fn test_dom_xss() {
        assert!(is_xss("document.write('<script>')"));
        assert!(is_xss("element.innerHTML = userInput"));
        assert!(is_xss("eval('malicious code')"));
    }
}
