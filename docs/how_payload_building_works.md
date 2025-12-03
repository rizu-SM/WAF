# How Payload Building Works in PyWAF

## Table of Contents
- [What Does This Function Do?](#what-does-this-function-do)
- [Step-by-Step Breakdown](#step-by-step-breakdown)
- [Visual Example](#visual-example)
- [Why Each Part?](#why-each-part)
  - [1. Why combine into one string?](#1-why-combine-into-one-string)
  - [2. Why `isinstance(args, dict)`?](#2-why-isinstanceargs-dict)
  - [3. Why only specific headers?](#3-why-only-specific-headers)
  - [4. Why truncate?](#4-why-truncate-payloadmax_payload_len)
- [Complete Example with Attack](#complete-example-with-attack)
- [Why This Design is Smart](#why-this-design-is-smart)
- [Summary](#summary)

---

## What Does This Function Do?

**Purpose:** Combines ALL parts of an HTTP request into ONE big string so detectors can search for attacks **everywhere at once**.

**Why?** Attackers can hide malicious code in:
- URL path
- Query parameters
- POST body
- Headers

Instead of checking each part separately, we combine them all!

---

## Step-by-Step Breakdown

### Example HTTP Request:
```http
POST /search?q=admin HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Referer: https://google.com
X-Forwarded-For: 192.168.1.1
Cookie: session=abc123

username=admin&password=1234
```

**Parsed into `req_dict`:**
```python
req_dict = {
    "path": "/search",
    "args": {"q": "admin"},
    "body": "username=admin&password=1234",
    "headers": {
        "user-agent": "Mozilla/5.0",
        "referer": "https://google.com",
        "x-forwarded-for": "192.168.1.1",
        "cookie": "session=abc123"
    }
}
```

---

### Now Let's Execute the Function:
```python
def build_payload_string(req_dict: dict) -> str:
    parts = []  # Empty list to collect pieces
    
    # STEP 1: Add the URL path
    parts.append(req_dict.get("path", ""))
    # parts = ["/search"]
    
    # STEP 2: Add query parameters
    args = req_dict.get("args") or {}
    # args = {"q": "admin"}
    
    if isinstance(args, dict):  # Check if it's a dictionary
        for k, v in args.items():
            parts.append(f"{k}={v}")
    # parts = ["/search", "q=admin"]
    
    else:
        parts.append(str(args))
    
    # STEP 3: Add the POST body
    parts.append(req_dict.get("body", "") or "")
    # parts = ["/search", "q=admin", "username=admin&password=1234"]
    
    # STEP 4: Add specific headers
    headers = req_dict.get("headers") or {}
    
    for h in ("user-agent", "referer", "x-forwarded-for"):
        if headers.get(h):
            parts.append(headers.get(h))
    # parts = [
    #     "/search",
    #     "q=admin",
    #     "username=admin&password=1234",
    #     "Mozilla/5.0",
    #     "https://google.com",
    #     "192.168.1.1"
    # ]
    
    # Notice: Cookie is NOT added (to avoid false positives from session tokens)
    
    # STEP 5: Combine everything with spaces
    payload = " ".join(parts)
    # payload = "/search q=admin username=admin&password=1234 Mozilla/5.0 https://google.com 192.168.1.1"
    
    # STEP 6: Truncate if too long (prevent memory issues)
    MAX_PAYLOAD_LEN = 2000
    if len(payload) > MAX_PAYLOAD_LEN:
        payload = payload[:MAX_PAYLOAD_LEN]
    
    return payload
```

---

## Visual Example

### Input (HTTP Request):
```http
POST /search?q=<script>alert(1)</script> HTTP/1.1
User-Agent: Hacker/1.0
Body: username=admin' OR 1=1--
```

### After `build_payload_string()`:
```
"/search q=<script>alert(1)</script> username=admin' OR 1=1-- Hacker/1.0"
```

**Now detectors can search this ONE string for:**
- XSS: `<script>`
- SQLi: `OR 1=1--`
- Suspicious user-agent: `Hacker/1.0`

---

## Why Each Part?

### 1. Why combine into one string?

**Without combining:**
```python
# Have to check each part separately (slow and error-prone)
if detect_xss(path):
    block()
if detect_xss(args):
    block()
if detect_xss(body):
    block()
if detect_xss(headers):
    block()
```

**With combining:**
```python
# Check everything at once (fast and simple)
payload = build_payload_string(req_dict)
if detect_xss(payload):
    block()
```

---

### 2. Why `isinstance(args, dict)`?

Sometimes `args` might not be a dictionary:
```python
# Normal case: args is a dict
args = {"page": "1", "sort": "name"}
# We want: "page=1 sort=name"

# Edge case: args might be a string or None
args = "page=1&sort=name"  # Already a string
# We want: "page=1&sort=name" (as-is)

args = None  # No arguments
# We want: "" (empty string)
```

**That's why we check:**
```python
if isinstance(args, dict):
    # Format as key=value pairs
    for k, v in args.items():
        parts.append(f"{k}={v}")
else:
    # Just convert to string as-is
    parts.append(str(args))
```

---

### 3. Why only specific headers?
```python
for h in ("user-agent", "referer", "x-forwarded-for"):
```

**Why not all headers?**

❌ **Headers to SKIP:**
- `cookie`: Contains session tokens like `session=abc123xyz...` (long random strings)
  - Would cause **false positives** (random characters might look like attacks)
- `content-length`: Just a number
- `host`: Usually safe domain name
- `accept`: Boring content types

✅ **Headers to CHECK:**
- `user-agent`: Attackers often use custom user-agents
- `referer`: Can contain malicious URLs
- `x-forwarded-for`: IP address (sometimes manipulated)

---

### 4. Why truncate (`payload[:MAX_PAYLOAD_LEN]`)?
```python
if len(payload) > MAX_PAYLOAD_LEN:
    payload = payload[:MAX_PAYLOAD_LEN]
```

**Reasons:**

1. **Memory:** A 10MB POST body would consume too much RAM
2. **Speed:** Regex on huge strings is SLOW
3. **Attacks are usually small:** Real attacks are typically < 1000 characters
4. **DoS prevention:** Attacker could send 1GB request to crash WAF

**Example:**
```python
# Huge malicious payload
huge_payload = "<script>alert(1)</script>" * 100000  # 2.5 MB!

# After truncation
truncated = huge_payload[:2000]  # Only first 2000 characters

# Still contains the attack!
"<script>alert(1)</script><script>alert(1)</script>..."
```

**The attack is still detected** because it appears in the first 2000 characters!

---

## Complete Example with Attack

### Attack Request:
```http
GET /search?file=../../etc/passwd&user=admin' OR 1=1-- HTTP/1.1
Host: example.com
User-Agent: <script>alert('XSS')</script>
Referer: javascript:alert(1)
X-Forwarded-For: 192.168.1.100
```

### After `build_payload_string()`:
```
"/search file=../../etc/passwd user=admin' OR 1=1-- <script>alert('XSS')</script> javascript:alert(1) 192.168.1.100"
```

### Detectors Find:
- **Path Traversal:** `../../etc/passwd`
- **SQL Injection:** `admin' OR 1=1--`
- **XSS:** `<script>alert('XSS')</script>`
- **XSS:** `javascript:alert(1)`

**All attacks found in ONE scan!** 🎯

---

## Why This Design is Smart

| Approach | Pros | Cons |
|----------|------|------|
| **Check each part separately** | More precise location | Slow, complex code, easy to miss attacks |
| **Combine into one string** (our approach) | Fast, simple, catches everything | Slightly less precise about location |

This approach is **much better** for a WAF because:
- ✅ Speed matters (checking thousands of requests/second)
- ✅ Simplicity matters (less bugs)
- ✅ Coverage matters (don't miss attacks)

---

## Summary
```python
# BEFORE:
req_dict = {
    "path": "/search",
    "args": {"q": "test"},
    "body": "username=admin",
    "headers": {"user-agent": "Mozilla/5.0"}
}

# AFTER build_payload_string():
payload = "/search q=test username=admin Mozilla/5.0"

# NOW DETECTORS CAN:
if "OR 1=1" in payload:  # Check EVERYTHING at once!
    block_request()
```

**Think of it like:** Taking all the puzzle pieces and laying them out in one line so you can see the whole picture at once! 🧩

---

## Related Documentation
- [SQL Injection Detection](../detection/sql_injection.md)
- [XSS Detection](../detection/xss.md)
- [Path Traversal Detection](../detection/path_traversal.md)
- [Pattern Matcher](../detection/pattern_matcher.md)
