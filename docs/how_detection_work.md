# PyWAF Detection System - Technical Documentation

## Overview
This document explains how the PyWAF (Python Web Application Firewall) detection system works from configuration loading to blocking malicious requests.

---

## 🔄 Detection Flow Architecture

### Phase 1: Configuration Loading (Startup)

When PyWAF initializes, it loads all detection rules and settings:

```python
# In waf.py __init__
self.config_loader = get_config_loader()
self.rules = self.config_loader.get_rules()  # Loads config/waf_rules.json
self.config = self.config_loader.get_config()  # Loads config/waf_config.yaml
```

**Configuration Files:**

1. **`config/waf_rules.json`** - Detection patterns (regex)
```json
{
  "sql_injection": [
    "union.*select",
    "drop\\s+table",
    "insert\\s+into",
    "exec\\s*\\("
  ],
  "xss": [
    "<script[^>]*>.*?</script>",
    "javascript:",
    "onerror\\s*=",
    "onclick\\s*="
  ],
  "path_traversal": [
    "\\.\\./",
    "\\.\\.\\\\",
    "/etc/passwd",
    "c:\\\\windows"
  ]
}
```

2. **`config/waf_config.yaml`** - WAF behavior settings
```yaml
waf:
  mode: block  # block, log, or challenge
  backend_url: http://localhost:8000
  
detection:
  sql_injection: true
  xss: true
  path_traversal: true
```

3. **`config/whitelist.json`** - Trusted IPs and paths
```json
{
  "ips": ["127.0.0.1", "::1"],
  "paths": ["/health", "/metrics"]
}
```

---

### Phase 2: Request Arrives

Example malicious HTTP request:

```http
GET /search?q=<script>alert('XSS')</script> HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Cookie: session=abc123
```

---

### Phase 3: Request Processing Pipeline

```python
def process_request(self, request: WAFRequest) -> WAFResponse:
    # Step 1: Check whitelists
    whitelist_reason = self._check_whitelists(request)
    if whitelist_reason:
        return WAFResponse(allowed=True, reason=whitelist_reason)
    
    # Step 2: Build request dictionary
    request_dict = self._build_request_dict(request)
    
    # Step 3: Run all detectors
    detection_results = self._run_detectors(request_dict)
    
    # Step 4: Make decision (block/allow/log)
    return self._make_decision(detection_results, request)
```

**Request Dictionary Structure:**
```python
{
    "method": "GET",
    "path": "/search",
    "args": {"q": "<script>alert('XSS')</script>"},
    "body": "",
    "headers": {
        "user-agent": "Mozilla/5.0",
        "cookie": "session=abc123"
    }
}
```

---

### Phase 4: Multi-Layer Detection Engine

#### 4.1 SQL Injection Detection

**Detection Layers:**

1. **Payload Normalization**
```python
payload = "/search q=<script>alert('XSS')</script> Mozilla/5.0"
normalized = normalize_payload(payload)  # URL-decode + lowercase
```

2. **Hardcoded Pattern Checks** (in `sql_injection.py`)
   - SQL Keywords: `SELECT`, `UNION`, `DROP`, `INSERT`, `DELETE`
   - SQL Comments: `--`, `#`, `/*`, `*/`
   - Logic Patterns: `OR 1=1`, `' OR '1'='1`, `AND 1=1`

3. **Config Pattern Matching** (from `waf_rules.json`)
```python
sql_patterns = self.rules.get('sql_injection', [])
regex_hits = match_patterns(normalized, sql_patterns)
# Checks: "union.*select", "drop\\s+table", etc.
```

4. **Confidence Scoring**
   - **High**: SQL comments + keywords detected
   - **Medium**: Multiple suspicious indicators
   - **Low**: Single keyword match

**Example Detection:**
```python
Request: GET /login?user=admin' OR '1'='1'--

Detection:
  ✓ Comment pattern: "--"
  ✓ Logic pattern: "OR '1'='1"
  ✓ Keyword: "OR"
  
Result: {
    "reason": "comment",
    "hits": ["--"],
    "confidence": "high"
}
```

---

#### 4.2 XSS (Cross-Site Scripting) Detection

**Detection Layers:**

1. **Dangerous HTML Tags**
```python
XSS_DANGEROUS_TAGS = [
    "script", "iframe", "object", "embed", 
    "applet", "meta", "link", "style"
]
tag_hits = _detect_dangerous_tags(payload, normalized)
```

2. **Event Handlers**
```python
XSS_EVENT_HANDLERS = [
    "onload", "onerror", "onclick", "onmouseover",
    "onfocus", "onblur", "onchange", "onsubmit"
]
event_hits = _detect_event_handlers(payload)
```

3. **JavaScript URI Schemes**
```python
XSS_URI_SCHEMES = ["javascript:", "data:", "vbscript:"]
uri_hits = _detect_js_uri_schemes(normalized)
```

4. **Dangerous JavaScript Functions**
```python
XSS_JS_FUNCTIONS = [
    "eval", "alert", "confirm", "prompt",
    "document.write", "document.cookie"
]
js_func_hits = _detect_js_functions(normalized)
```

5. **Encoded Attack Detection**
```python
# Detects URL-encoded, HTML-encoded, Unicode variants
# Examples: %3Cscript%3E, &lt;script&gt;, \u003cscript\u003e
encoded_hits = _detect_encoded_attacks(payload)
```

6. **Obfuscation Detection**
```python
# Detects mixed case, whitespace tricks, string concatenation
# Examples: <ScRiPt>, < script >, 'al'+'ert'
obfuscation_hits = _detect_obfuscation(payload, normalized)
```

7. **Config Pattern Matching**
```python
xss_patterns = self.rules.get('xss', [])
regex_hits = match_patterns(normalized, xss_patterns)
# Checks: "<script[^>]*>.*?</script>", "javascript:", etc.
```

**Example Detection:**
```python
Request: GET /search?q=<script>alert(1)</script>

Detection Timeline:
  [0.001s] Normalize payload
  [0.002s] ✓ Dangerous tag: "script"
  [0.003s] ✓ JS function: "alert"
  [0.004s] ✓ Config pattern: "<script[^>]*>.*?</script>"
  [0.005s] Confidence: HIGH
  
Result: {
    "reason": "dangerous_tags",
    "hits": ["script"],
    "confidence": "high"
}
```

---

#### 4.3 Path Traversal Detection

**Detection Layers:**

1. **Directory Traversal Sequences**
```python
PATH_TRAVERSAL_PATTERNS = [
    "../", "..\\", "%2e%2e/", "%2e%2e\\",
    "..%2f", "..%5c"
]
```

2. **Sensitive File Access**
```python
SENSITIVE_FILES = [
    "/etc/passwd", "/etc/shadow", "c:\\windows\\system32",
    "web.config", ".htaccess", ".env"
]
```

3. **Config Pattern Matching**
```python
path_patterns = self.rules.get('path_traversal', [])
regex_hits = match_patterns(normalized, path_patterns)
```

**Example Detection:**
```python
Request: GET /download?file=../../../../etc/passwd

Detection:
  ✓ Traversal sequence: "../"
  ✓ Sensitive file: "/etc/passwd"
  ✓ Multiple traversal attempts: 4
  
Result: {
    "reason": "traversal_sequence",
    "hits": ["../"],
    "confidence": "high"
}
```

---

### Phase 5: Result Aggregation

```python
detection_results = {
    "detections": [
        {
            "type": "xss",
            "details": {
                "reason": "dangerous_tags",
                "hits": ["script"],
                "confidence": "high"
            }
        }
    ],
    "high_confidence_attack": True,
    "block_recommended": True
}
```

---

### Phase 6: Decision Making

```python
def _make_decision(self, detection_results, request):
    waf_mode = self.config.get('waf', {}).get('mode', 'log')
    
    # Priority 1: High confidence attacks → always block
    if detection_results["high_confidence_attack"]:
        return WAFResponse(
            allowed=False,
            action="block",
            reason="high_confidence_xss",
            confidence="high",
            status_code=403
        )
    
    # Priority 2: WAF mode behavior
    if waf_mode == "block":
        return WAFResponse(allowed=False, action="block", status_code=403)
    
    elif waf_mode == "log":
        # Log attack but allow request
        return WAFResponse(allowed=True, action="log", status_code=200)
    
    elif waf_mode == "challenge":
        # Present CAPTCHA or additional verification
        return WAFResponse(allowed=False, action="challenge", status_code=401)
```

---

### Phase 7: Response & Logging

**Blocked Response:**
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "Request blocked by WAF",
  "reason": "XSS attack detected",
  "request_id": "abc123"
}
```

**Logging (to `logs/waf.log`):**
```
2025-11-22 10:30:45 - WARNING - BLOCKED: GET /search from 192.168.1.100
  Reason: high_confidence_xss
  Details: {"attack_type": "xss", "hits": ["script"], "confidence": "high"}
```

---

## 🎯 Complete Attack Detection Example

### Scenario: XSS Attack

**1. Attack Request:**
```http
GET /comment?text=<img src=x onerror=alert(document.cookie)> HTTP/1.1
```

**2. Detection Process:**

| Time | Layer | Result |
|------|-------|--------|
| 0.001s | Load config | Rules loaded from waf_rules.json |
| 0.002s | Build payload | `/comment text=<img src=x onerror=alert(document.cookie)>` |
| 0.003s | Normalize | Lowercase, URL-decode |
| 0.004s | Tag check | ✓ Found: `img` (dangerous tag) |
| 0.005s | Event check | ✓ Found: `onerror` (event handler) |
| 0.006s | JS function check | ✓ Found: `alert` (dangerous function) |
| 0.007s | Config pattern | ✓ Match: `onerror\\s*=` |
| 0.008s | Confidence | **HIGH** (3 high-confidence indicators) |
| 0.009s | Decision | **BLOCK** (mode=block, high_confidence=true) |
| 0.010s | Response | 403 Forbidden |

**3. Detection Result:**
```python
{
    "allowed": False,
    "action": "block",
    "reason": "high_confidence_xss",
    "confidence": "high",
    "status_code": 403,
    "details": {
        "attack_type": "xss",
        "detection_details": {
            "reason": "event_handlers",
            "hits": ["onerror"],
            "sample": "/comment text=<img src=x onerror=alert(...)",
            "confidence": "high"
        }
    }
}
```

---

## 🛡️ Defense-in-Depth Strategy

### Why Multiple Detection Layers?

1. **Hardcoded Patterns** (Fast, Pre-compiled)
   - Common attack signatures
   - Built-in obfuscation detection
   - No external dependencies

2. **Config Patterns** (Flexible, Updatable)
   - Custom rules for specific applications
   - Easy to update without code changes
   - Can adapt to new attack variants

3. **Combined Power**
   ```python
   if hardcoded_match OR config_pattern_match:
       confidence = "high"
       block_request()
   ```

### Evasion Techniques Detected

| Technique | Example | Detection Method |
|-----------|---------|------------------|
| URL Encoding | `%3Cscript%3E` | Normalization + pattern match |
| HTML Encoding | `&lt;script&gt;` | HTML unescape + tag detection |
| Unicode | `\u003cscript\u003e` | Encoded attack detection |
| Mixed Case | `<ScRiPt>` | Lowercase normalization |
| Whitespace | `< script >` | Obfuscation detection |
| String Concat | `'al'+'ert'` | JavaScript function detection |
| Comment Tricks | `--+` in SQL | Comment pattern matching |

---

## 📊 Performance Considerations

### Optimization Techniques

1. **Pattern Caching**
```python
_precompiled_cache = {}  # Cache compiled regex

def compile_pattern(pat):
    if pat in _precompiled_cache:
        return _precompiled_cache[pat]
    regex = re.compile(pat, re.IGNORECASE)
    _precompiled_cache[pat] = regex
    return regex
```

2. **Payload Length Limits**
```python
MAX_PAYLOAD_LEN = 2000  # Truncate very long payloads
```

3. **Early Exit on Whitelist**
```python
# Skip detection for whitelisted IPs/paths
if ip in whitelist or path in whitelist_paths:
    return allow_request()
```

4. **Sequential Detection** (stops on first high-confidence match)
```python
for detector in [sql_injection, xss, path_traversal]:
    if high_confidence_match:
        return block_immediately()
```

---

## 🔧 Configuration Best Practices

### 1. WAF Mode Selection

- **Development**: `mode: log` (log attacks, don't block)
- **Staging**: `mode: challenge` (verify suspicious requests)
- **Production**: `mode: block` (block confirmed attacks)

### 2. Pattern Management

```json
{
  "sql_injection": [
    "(?i)union.*select",      // Case-insensitive
    "drop\\s+table",           // Whitespace handling
    "exec\\s*\\(",             // Function calls
    "xp_cmdshell"              // Dangerous stored procedures
  ]
}
```

### 3. Whitelist Management

```json
{
  "ips": [
    "127.0.0.1",              // Localhost
    "10.0.0.0/8",             // Internal network
    "2001:db8::/32"           // IPv6 range
  ],
  "paths": [
    "/health",                // Health check endpoint
    "/metrics",               // Monitoring endpoint
    "/static/.*"              // Static assets (regex)
  ]
}
```

---

## 📈 Monitoring & Metrics

### Key Metrics Tracked

```python
{
    "total_requests": 1000,
    "blocked": 50,
    "allowed": 950,
    "block_rate_percent": 5.0,
    "attacks_by_type": {
        "sql_injection": {"detected": 20, "blocked": 20},
        "xss": {"detected": 25, "blocked": 25},
        "path_traversal": {"detected": 5, "blocked": 5}
    }
}
```

### Log Analysis

```bash
# View blocked requests
grep "BLOCKED" logs/waf.log

# Count attacks by type
grep "xss" logs/waf.log | wc -l

# Find high-confidence attacks
grep "high_confidence" logs/waf.log
```

---

## 🎓 Conclusion

PyWAF implements a **multi-layered, defense-in-depth approach** to web application security:

1. **Configuration-Driven**: Easy to customize and update
2. **Performance-Optimized**: Pattern caching, early exits
3. **Comprehensive Coverage**: Multiple detection techniques per attack type
4. **Evasion-Resistant**: Handles encoding, obfuscation, case tricks
5. **Observable**: Detailed logging and metrics

This architecture provides robust protection while maintaining flexibility for different deployment scenarios.

---
