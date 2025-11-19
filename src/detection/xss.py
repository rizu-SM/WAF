# src/detection/xss.py
import re
from typing import Tuple, List, Dict, Optional
from .pattern_matcher import match_patterns, normalize_payload


# Configurable limits
MAX_PAYLOAD_LEN = 2000
MIN_INDICATORS_TO_BLOCK = 2

# XSS-specific dangerous HTML tags
XSS_DANGEROUS_TAGS = [
    "script", "iframe", "object", "embed", "applet", "meta",
    "link", "style", "base", "form", "input", "button"
]

# XSS event handlers (JavaScript execution)
XSS_EVENT_HANDLERS = [
    "onload", "onerror", "onclick", "onmouseover", "onmouseout",
    "onfocus", "onblur", "onchange", "onsubmit", "onkeydown",
    "onkeyup", "onkeypress", "ondblclick", "onmousedown", "onmouseup",
    "oncontextmenu", "oninput", "onabort", "onbeforeunload", "onhashchange"
]

# JavaScript URI schemes
JS_URI_SCHEMES = [
    "javascript:", "data:", "vbscript:", "file:", "about:"
]

# Dangerous JavaScript functions
DANGEROUS_JS_FUNCTIONS = [
    "eval", "alert", "confirm", "prompt", "settimeout", "setinterval",
    "document.write", "document.writeln", "innerhtml", "outerhtml",
    "document.cookie", "window.location", "document.location"
]

# Precompile patterns for performance
_COMPILED_TAG_PATTERNS = [
    re.compile(r'<\s*' + tag + r'[^>]*>', re.IGNORECASE) 
    for tag in XSS_DANGEROUS_TAGS
]

_COMPILED_EVENT_PATTERNS = [
    re.compile(r'\b' + event + r'\s*=', re.IGNORECASE)
    for event in XSS_EVENT_HANDLERS
]

_COMPILED_JS_FUNCTION_PATTERNS = [
    re.compile(r'\b' + func.replace('.', r'\.') + r'\s*\(', re.IGNORECASE)
    for func in DANGEROUS_JS_FUNCTIONS
]


def build_payload_string(req_dict: dict) -> str:
    """Build complete payload from request components"""
    parts = []
    parts.append(req_dict.get("path", ""))
    
    args = req_dict.get("args") or {}
    if isinstance(args, dict):
        for k, v in args.items():
            parts.append(f"{k}={v}")
    else:
        parts.append(str(args))
    
    parts.append(req_dict.get("body", "") or "")
    
    headers = req_dict.get("headers") or {}
    for h in ("user-agent", "referer", "x-forwarded-for", "cookie"):
        if headers.get(h):
            parts.append(headers.get(h))
    
    payload = " ".join(parts)
    
    # Truncate overly long payloads
    if len(payload) > MAX_PAYLOAD_LEN:
        payload = payload[:MAX_PAYLOAD_LEN]
    
    return payload


def _detect_dangerous_tags(payload: str, normalized: str) -> List[str]:
    """Detect dangerous HTML tags"""
    hits = []
    for pattern, tag in zip(_COMPILED_TAG_PATTERNS, XSS_DANGEROUS_TAGS):
        if pattern.search(payload):  # Search in original payload (case-sensitive HTML)
            hits.append(tag)
    return hits


def _detect_event_handlers(payload: str) -> List[str]:
    """Detect JavaScript event handlers"""
    hits = []
    for pattern, event in zip(_COMPILED_EVENT_PATTERNS, XSS_EVENT_HANDLERS):
        if pattern.search(payload):
            hits.append(event)
    return hits


def _detect_js_uri_schemes(normalized: str) -> List[str]:
    """Detect dangerous URI schemes"""
    hits = []
    for scheme in JS_URI_SCHEMES:
        if scheme in normalized:
            hits.append(scheme)
    return hits


def _detect_js_functions(normalized: str) -> List[str]:
    """Detect dangerous JavaScript functions"""
    hits = []
    for pattern, func in zip(_COMPILED_JS_FUNCTION_PATTERNS, DANGEROUS_JS_FUNCTIONS):
        if pattern.search(normalized):
            hits.append(func)
    return hits


def _detect_encoded_attacks(payload: str) -> List[str]:
    """Detect encoded XSS attempts (HTML entities, URL encoding, etc.)"""
    hits = []
    
    # HTML entity encoding: &lt;script&gt;
    if re.search(r'&lt;.*?&gt;', payload, re.IGNORECASE):
        hits.append("html_entity_encoding")
    
    # URL encoding: %3Cscript%3E
    if re.search(r'%3[Cc].*?%3[Ee]', payload):
        hits.append("url_encoding")
    
    # Unicode encoding: \u003cscript\u003e
    if re.search(r'\\u00[0-9a-fA-F]{2}', payload):
        hits.append("unicode_encoding")
    
    # Hex encoding: \x3cscript\x3e
    if re.search(r'\\x[0-9a-fA-F]{2}', payload):
        hits.append("hex_encoding")
    
    return hits


def _detect_obfuscation(payload: str, normalized: str) -> List[str]:
    """Detect obfuscation techniques"""
    hits = []
    
    # Excessive whitespace/newlines in tags: <   script   >
    if re.search(r'<\s{3,}\w+', payload):
        hits.append("tag_whitespace_obfuscation")
    
    # Mixed case to evade filters: <ScRiPt>
    if re.search(r'<[a-zA-Z]+>', payload):
        tags = re.findall(r'<([a-zA-Z]+)>', payload)
        for tag in tags:
            if tag.lower() in XSS_DANGEROUS_TAGS and tag != tag.lower():
                hits.append("mixed_case_obfuscation")
                break
    
    # String concatenation: 'java'+'script:'
    if re.search(r"['\"][\s]*\+[\s]*['\"]", normalized):
        hits.append("string_concatenation")
    
    # Backslash obfuscation: j\ava\script
    if re.search(r'\w\\+\w', payload):
        hits.append("backslash_obfuscation")
    
    return hits


def detect_xss(req_dict: dict, patterns: Optional[List[str]] = None) -> Tuple[bool, Dict]:
    """
    Detect XSS (Cross-Site Scripting) attacks
    
    Returns (is_attack, details)
    details contains: reason, hits/list, sample, confidence
    """
    payload = build_payload_string(req_dict)
    normalized = normalize_payload(payload)
    sample = payload[:300]
    
    indicators = []
    
    # 1) Dangerous HTML tags (high confidence)
    tag_hits = _detect_dangerous_tags(payload, normalized)
    if tag_hits:
        indicators.append({"type": "dangerous_tags", "hits": tag_hits})
    
    # 2) Event handlers (high confidence)
    event_hits = _detect_event_handlers(payload)
    if event_hits:
        indicators.append({"type": "event_handlers", "hits": event_hits})
    
    # 3) JavaScript URI schemes (high confidence)
    uri_hits = _detect_js_uri_schemes(normalized)
    if uri_hits:
        indicators.append({"type": "js_uri_schemes", "hits": uri_hits})
    
    # 4) Dangerous JavaScript functions (medium confidence)
    js_func_hits = _detect_js_functions(normalized)
    if js_func_hits:
        indicators.append({"type": "js_functions", "hits": js_func_hits})
    
    # 5) Encoded attacks (high confidence)
    encoded_hits = _detect_encoded_attacks(payload)
    if encoded_hits:
        indicators.append({"type": "encoded_attacks", "hits": encoded_hits})
    
    # 6) Obfuscation techniques (medium confidence)
    obfuscation_hits = _detect_obfuscation(payload, normalized)
    if obfuscation_hits:
        indicators.append({"type": "obfuscation", "hits": obfuscation_hits})
    
    # 7) Regex patterns from rules (high confidence if matched)
    regex_hits = []
    if patterns:
        regex_hits = match_patterns(normalized, patterns)
        if regex_hits:
            indicators.append({"type": "regex", "hits": regex_hits})
    
    # Decision logic:
    # - High confidence indicators: dangerous_tags, event_handlers, js_uri_schemes, encoded_attacks, regex
    # - Medium confidence: js_functions, obfuscation
    # - Block if any high-confidence indicator found
    # - Block if >= MIN_INDICATORS_TO_BLOCK total indicators
    
    high_conf_types = {"dangerous_tags", "event_handlers", "js_uri_schemes", "encoded_attacks", "regex"}
    
    for ind in indicators:
        if ind["type"] in high_conf_types:
            return True, {
                "reason": ind["type"],
                "hits": ind.get("hits", []),
                "sample": sample,
                "confidence": "high"
            }
    
    # Check total indicators for medium confidence block
    if len(indicators) >= MIN_INDICATORS_TO_BLOCK:
        return True, {
            "reason": "combined_indicators",
            "indicators": indicators,
            "sample": sample,
            "confidence": "medium"
        }
    
    # Low confidence: single medium-confidence indicator -> log only
    if indicators:
        return False, {
            "reason": "low_confidence_indicators",
            "indicators": indicators,
            "sample": sample,
            "confidence": "low"
        }
    
    return False, {}


# Self-test
if __name__ == "__main__":
    print("🧪 Testing XSS Detection\n")
    print("=" * 60)
    
    # Test 1: Clean request
    print("\n[TEST 1] Clean Request")
    clean_request = {
        "path": "/profile",
        "args": {"name": "John Doe", "age": "25"},
        "body": "",
        "headers": {"user-agent": "Mozilla/5.0"}
    }
    
    is_attack, details = detect_xss(clean_request)
    print(f"Attack detected: {is_attack}")
    print(f"Details: {details}")
    
    # Test 2: Script tag injection
    print("\n[TEST 2] Script Tag Injection")
    script_request = {
        "path": "/search",
        "args": {"q": "<script>alert('XSS')</script>"},
        "body": "",
        "headers": {"user-agent": "Mozilla/5.0"}
    }
    
    is_attack, details = detect_xss(script_request)
    print(f"Attack detected: {is_attack}")
    print(f"Details: {details}")
    
    # Test 3: Event handler injection
    print("\n[TEST 3] Event Handler Injection")
    event_request = {
        "path": "/comment",
        "args": {},
        "body": "comment=<img src=x onerror=alert(1)>",
        "headers": {"user-agent": "Mozilla/5.0"}
    }
    
    is_attack, details = detect_xss(event_request)
    print(f"Attack detected: {is_attack}")
    print(f"Details: {details}")
    
    # Test 4: JavaScript URI
    print("\n[TEST 4] JavaScript URI")
    js_uri_request = {
        "path": "/redirect",
        "args": {"url": "javascript:alert('XSS')"},
        "body": "",
        "headers": {"user-agent": "Mozilla/5.0"}
    }
    
    is_attack, details = detect_xss(js_uri_request)
    print(f"Attack detected: {is_attack}")
    print(f"Details: {details}")
    
    # Test 5: Encoded attack
    print("\n[TEST 5] Encoded XSS Attack")
    encoded_request = {
        "path": "/search",
        "args": {"q": "%3Cscript%3Ealert('XSS')%3C/script%3E"},
        "body": "",
        "headers": {"user-agent": "Mozilla/5.0"}
    }
    
    is_attack, details = detect_xss(encoded_request)
    print(f"Attack detected: {is_attack}")
    print(f"Details: {details}")
    
    # Test 6: Iframe injection
    print("\n[TEST 6] Iframe Injection")
    iframe_request = {
        "path": "/post",
        "args": {},
        "body": "content=<iframe src='http://evil.com'></iframe>",
        "headers": {"user-agent": "Mozilla/5.0"}
    }
    
    is_attack, details = detect_xss(iframe_request)
    print(f"Attack detected: {is_attack}")
    print(f"Details: {details}")
    
    # Test 7: Multiple indicators (medium confidence)
    print("\n[TEST 7] Multiple Indicators")
    multi_request = {
        "path": "/update",
        "args": {"data": "eval(alert(1))"},
        "body": "",
        "headers": {"user-agent": "Mozilla/5.0"}
    }
    
    is_attack, details = detect_xss(multi_request)
    print(f"Attack detected: {is_attack}")
    print(f"Details: {details}")
    
    print("\n" + "=" * 60)
    print("✅ XSS detection test completed!")
