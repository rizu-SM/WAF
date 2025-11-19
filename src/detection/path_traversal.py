# src/detection/path_traversal.py
import re
import urllib.parse
from typing import Tuple, List, Dict, Optional, Any
from .pattern_matcher import match_patterns, normalize_payload


# Configurable limits
MAX_PAYLOAD_LEN = 2000
MIN_INDICATORS_TO_BLOCK = 2

# Path traversal patterns
PATH_TRAVERSAL_SEQUENCES = [
    "..",           # Basic directory traversal
    "..\\",         # Windows style
    "../",          # Unix style
    "..;/",         # Semicolon bypass
    "%2e%2e",       # URL encoded ..
    "%252e%252e",   # Double URL encoded ..
    "..%2f",        # Mixed encoding
    "..%5c",        # Mixed encoding (backslash)
    "..%c0%af",     # UTF-8 encoding
    "..%c1%9c",     # Overlong UTF-8
]

# Dangerous file access patterns
DANGEROUS_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "etc/passwd",
    "etc/shadow",
    "windows/system32",
    "winnt/system32",
    "boot.ini",
    "win.ini",
    "/proc/self",
    "c:\\windows",
    "c:/windows",
]

# Null byte injection patterns
NULL_BYTE_PATTERNS = [
    "%00",          # URL encoded null byte
    "\\x00",        # Hex null byte
    "\x00",         # Actual null byte
    "%u0000",       # Unicode null byte
]

# Precompile patterns for performance
_COMPILED_TRAVERSAL_PATTERNS = [
    re.compile(re.escape(seq), re.IGNORECASE) 
    for seq in PATH_TRAVERSAL_SEQUENCES
]

_COMPILED_DANGEROUS_PATHS = [
    re.compile(re.escape(path), re.IGNORECASE) 
    for path in DANGEROUS_PATHS
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


def _detect_traversal_sequences(payload: str) -> List[str]:
    """Detect directory traversal sequences"""
    hits = []
    for pattern, seq in zip(_COMPILED_TRAVERSAL_PATTERNS, PATH_TRAVERSAL_SEQUENCES):
        if pattern.search(payload):
            hits.append(seq)
    return hits


def _detect_dangerous_paths(payload: str, normalized: str) -> List[str]:
    """Detect access to dangerous system files/directories"""
    hits = []
    for pattern, path in zip(_COMPILED_DANGEROUS_PATHS, DANGEROUS_PATHS):
        if pattern.search(normalized):
            hits.append(path)
    return hits


def _detect_null_bytes(payload: str) -> List[str]:
    """Detect null byte injection attempts"""
    hits = []
    for null_pattern in NULL_BYTE_PATTERNS:
        if null_pattern in payload:
            hits.append(null_pattern)
    return hits


def _detect_absolute_paths(payload: str, normalized: str) -> List[str]:
    """Detect absolute path access attempts"""
    hits = []
    
    # Unix absolute paths: /etc/, /var/, /usr/, /root/, etc.
    unix_absolute = re.findall(r'(?:^|[\s\'"?&=])(/(?:etc|var|usr|root|proc|sys|boot|dev|tmp|opt)/[^\s\'"?&]*)', normalized)
    if unix_absolute:
        hits.extend(unix_absolute)
    
    # Windows absolute paths: C:\, D:\, etc.
    windows_absolute = re.findall(r'(?:[a-z]:|\\\\)[:\\\/](?:windows|winnt|system32|program\s*files)', normalized, re.IGNORECASE)
    if windows_absolute:
        hits.extend(windows_absolute)
    
    return hits


def _detect_excessive_traversal(payload: str) -> Dict[str, int]:
    """Detect excessive directory traversal attempts (suspicious pattern)"""
    # Count consecutive .. patterns
    consecutive_dots = len(re.findall(r'(?:\.\.[\\/]){3,}', payload))  # 3+ consecutive traversals
    
    # Count total .. occurrences
    total_dots = payload.count('..')
    
    if consecutive_dots > 0 or total_dots > 5:
        return {
            "consecutive_traversals": consecutive_dots,
            "total_traversals": total_dots
        }
    
    return {}


def _detect_encoding_bypass(payload: str) -> List[str]:
    """Detect various encoding bypass attempts"""
    hits = []
    
    # Double URL encoding: %252e = %2e = .
    if re.search(r'%25[0-9a-fA-F]{2}', payload):
        hits.append("double_url_encoding")
    
    # UTF-8 overlong encoding
    if re.search(r'%c0%[a-fA-F0-9]{2}', payload, re.IGNORECASE):
        hits.append("utf8_overlong")
    
    # Unicode encoding
    if re.search(r'%u[0-9a-fA-F]{4}', payload, re.IGNORECASE):
        hits.append("unicode_encoding")
    
    # Backslash variations: \\, \\\, \\\\ (only multiple backslashes)
    if re.search(r'\\{3,}', payload):
        hits.append("backslash_repetition")
    
    # Forward slash variations in suspicious contexts (not normal URLs)
    # Only flag if we have // with traversal indicators nearby
    if re.search(r'/{3,}', payload) or (re.search(r'//', payload) and '..' in payload):
        hits.append("forward_slash_repetition")
    
    return hits


def _analyze_path_structure(path: str) -> Dict[str, Any]:
    """Analyze the structure of the request path for anomalies"""
    anomalies = []
    
    # Decode URL to check actual path
    try:
        decoded_path = urllib.parse.unquote(path)
    except:
        decoded_path = path
    
    # Check for too many directory levels (suspicious)
    levels = decoded_path.count('/') + decoded_path.count('\\')
    if levels > 10:
        anomalies.append(f"excessive_depth:{levels}")
    
    # Check for mixed path separators (suspicious)
    if '/' in decoded_path and '\\' in decoded_path:
        anomalies.append("mixed_separators")
    
    # Check for hidden files/directories
    if re.search(r'/\.(?!\.)[^/]*', decoded_path):  # Matches /. but not /..
        anomalies.append("hidden_file_access")
    
    # Check for path with no extension but traversal (suspicious)
    if '..' in decoded_path and not re.search(r'\.[a-zA-Z0-9]{2,5}$', decoded_path):
        anomalies.append("traversal_no_extension")
    
    return {
        "anomalies": anomalies,
        "path_depth": levels
    } if anomalies else {}


def detect_path_traversal(req_dict: dict, patterns: Optional[List[str]] = None) -> Tuple[bool, Dict]:
    """
    Detect Path Traversal attacks
    
    Returns (is_attack, details)
    details contains: reason, hits/list, sample, confidence
    """
    payload = build_payload_string(req_dict)
    normalized = normalize_payload(payload)
    sample = payload[:300]
    path = req_dict.get("path", "")
    
    indicators = []
    
    # 1) Directory traversal sequences (high confidence)
    traversal_hits = _detect_traversal_sequences(payload)
    if traversal_hits:
        indicators.append({"type": "traversal_sequences", "hits": traversal_hits})
    
    # 2) Dangerous system paths (high confidence)
    dangerous_path_hits = _detect_dangerous_paths(payload, normalized)
    if dangerous_path_hits:
        indicators.append({"type": "dangerous_paths", "hits": dangerous_path_hits})
    
    # 3) Null byte injection (high confidence)
    null_byte_hits = _detect_null_bytes(payload)
    if null_byte_hits:
        indicators.append({"type": "null_byte_injection", "hits": null_byte_hits})
    
    # 4) Absolute path access (high confidence)
    absolute_path_hits = _detect_absolute_paths(payload, normalized)
    if absolute_path_hits:
        indicators.append({"type": "absolute_paths", "hits": absolute_path_hits})
    
    # 5) Excessive traversal attempts (medium confidence)
    excessive_traversal = _detect_excessive_traversal(payload)
    if excessive_traversal:
        indicators.append({"type": "excessive_traversal", "details": excessive_traversal})
    
    # 6) Encoding bypass attempts (high confidence)
    encoding_hits = _detect_encoding_bypass(payload)
    if encoding_hits:
        indicators.append({"type": "encoding_bypass", "hits": encoding_hits})
    
    # 7) Path structure anomalies (medium confidence)
    path_anomalies = _analyze_path_structure(path)
    if path_anomalies:
        indicators.append({"type": "path_anomalies", "details": path_anomalies})
    
    # 8) Regex patterns from rules (high confidence if matched)
    regex_hits = []
    if patterns:
        regex_hits = match_patterns(normalized, patterns)
        if regex_hits:
            indicators.append({"type": "regex", "hits": regex_hits})
    
    # Decision logic:
    # - High confidence indicators: traversal_sequences, dangerous_paths, null_byte_injection, 
    #                               absolute_paths, encoding_bypass, regex
    # - Medium confidence: excessive_traversal, path_anomalies
    # - Block if any high-confidence indicator found
    # - Block if >= MIN_INDICATORS_TO_BLOCK total indicators
    
    high_conf_types = {
        "traversal_sequences", "dangerous_paths", "null_byte_injection",
        "absolute_paths", "encoding_bypass", "regex"
    }
    
    for ind in indicators:
        if ind["type"] in high_conf_types:
            return True, {
                "reason": ind["type"],
                "hits": ind.get("hits", []) or ind.get("details", {}),
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
    print("🧪 Testing Path Traversal Detection\n")
    print("=" * 60)
    
    # Test 1: Clean request
    print("\n[TEST 1] Clean Request")
    clean_request = {
        "path": "/api/files/document.pdf",
        "args": {"id": "12345"},
        "body": "",
        "headers": {"user-agent": "Mozilla/5.0"}
    }
    
    is_attack, details = detect_path_traversal(clean_request)
    print(f"Attack detected: {is_attack}")
    print(f"Details: {details}")
    
    # Test 2: Basic directory traversal
    print("\n[TEST 2] Basic Directory Traversal (../)")
    traversal_request = {
        "path": "/files",
        "args": {"file": "../../etc/passwd"},
        "body": "",
        "headers": {"user-agent": "Mozilla/5.0"}
    }
    
    is_attack, details = detect_path_traversal(traversal_request)
    print(f"Attack detected: {is_attack}")
    print(f"Details: {details}")
    
    # Test 3: Windows path traversal
    print("\n[TEST 3] Windows Path Traversal")
    windows_request = {
        "path": "/download",
        "args": {"file": "..\\..\\windows\\system32\\config\\sam"},
        "body": "",
        "headers": {"user-agent": "Mozilla/5.0"}
    }
    
    is_attack, details = detect_path_traversal(windows_request)
    print(f"Attack detected: {is_attack}")
    print(f"Details: {details}")
    
    # Test 4: URL encoded traversal
    print("\n[TEST 4] URL Encoded Traversal")
    encoded_request = {
        "path": "/files",
        "args": {"path": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
        "body": "",
        "headers": {"user-agent": "Mozilla/5.0"}
    }
    
    is_attack, details = detect_path_traversal(encoded_request)
    print(f"Attack detected: {is_attack}")
    print(f"Details: {details}")
    
    # Test 5: Null byte injection
    print("\n[TEST 5] Null Byte Injection")
    null_byte_request = {
        "path": "/view",
        "args": {"file": "../../etc/passwd%00.jpg"},
        "body": "",
        "headers": {"user-agent": "Mozilla/5.0"}
    }
    
    is_attack, details = detect_path_traversal(null_byte_request)
    print(f"Attack detected: {is_attack}")
    print(f"Details: {details}")
    
    # Test 6: Absolute path access
    print("\n[TEST 6] Absolute Path Access")
    absolute_request = {
        "path": "/files",
        "args": {"file": "/etc/passwd"},
        "body": "",
        "headers": {"user-agent": "Mozilla/5.0"}
    }
    
    is_attack, details = detect_path_traversal(absolute_request)
    print(f"Attack detected: {is_attack}")
    print(f"Details: {details}")
    
    # Test 7: Double URL encoding
    print("\n[TEST 7] Double URL Encoding")
    double_encoded_request = {
        "path": "/download",
        "args": {"file": "%252e%252e%252f%252e%252e%252fetc%252fpasswd"},
        "body": "",
        "headers": {"user-agent": "Mozilla/5.0"}
    }
    
    is_attack, details = detect_path_traversal(double_encoded_request)
    print(f"Attack detected: {is_attack}")
    print(f"Details: {details}")
    
    # Test 8: Excessive traversal
    print("\n[TEST 8] Excessive Directory Traversal")
    excessive_request = {
        "path": "/files",
        "args": {"path": "../../../../../../../../../etc/passwd"},
        "body": "",
        "headers": {"user-agent": "Mozilla/5.0"}
    }
    
    is_attack, details = detect_path_traversal(excessive_request)
    print(f"Attack detected: {is_attack}")
    print(f"Details: {details}")
    
    print("\n" + "=" * 60)
    print("✅ Path traversal detection test completed!")
