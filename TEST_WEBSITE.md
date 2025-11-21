# WAF Test Website

## Quick Start Guide

This test website demonstrates the capabilities of the custom Web Application Firewall (WAF). It includes various endpoints vulnerable to common web attacks, allowing you to test how the WAF detects and blocks malicious requests.

## Installation & Setup

### 1. Install Dependencies

Make sure you have Python installed, then install the required packages:

```bash
pip install -r requirements.txt
```

### 2. Run the Application

```bash
python app.py
```

The website will be available at: **http://127.0.0.1:5000**

## Test Endpoints

### 1. **Home Page** (`/`)
- Overview of the application
- Links to all test endpoints

### 2. **Contact Form** (`/contact`)
- **Purpose**: Test XSS and SQL Injection in form data
- **Test Examples**:
  - XSS: `<script>alert('XSS')</script>` in any field
  - SQL Injection: `' OR '1'='1` in any field

### 3. **Search** (`/search`)
- **Purpose**: Test XSS in query parameters
- **Test URLs**:
  - `http://127.0.0.1:5000/search?q=<script>alert(1)</script>`
  - `http://127.0.0.1:5000/search?q=<img src=x onerror=alert(1)>`

### 4. **File Viewer** (`/files`)
- **Purpose**: Test path traversal attacks
- **Test URLs**:
  - `http://127.0.0.1:5000/files?file=../../../etc/passwd`
  - `http://127.0.0.1:5000/files?file=..\\..\\..\\windows\\system32\\config\\sam`

### 5. **API Users** (`/api/users`)
- **Purpose**: Test SQL Injection in API endpoints
- **Test URLs**:
  - `http://127.0.0.1:5000/api/users?id=' OR '1'='1`
  - `http://127.0.0.1:5000/api/users?filter=' UNION SELECT * FROM users--`

### 6. **User Profile** (`/user/<username>`)
- **Purpose**: Test XSS and path traversal in URL paths
- **Test URLs**:
  - `http://127.0.0.1:5000/user/<script>alert(1)</script>`
  - `http://127.0.0.1:5000/user/../../etc/passwd`

### 7. **Test Payloads Page** (`/test/payloads`)
- Interactive page with buttons to test various malicious payloads
- Includes SQL Injection, XSS, and Path Traversal examples
- Shows real-time results of WAF blocking

### 8. **WAF Status** (`/waf/status`)
- Check if WAF is active and protecting the application

## Testing Workflow

### Manual Testing

1. **Start the server**: Run `python app.py`
2. **Open your browser**: Go to http://127.0.0.1:5000
3. **Try legitimate requests**: Navigate normally to ensure the site works
4. **Test malicious payloads**: Try the examples below

### Example Malicious Payloads

#### SQL Injection
```
' OR '1'='1
' UNION SELECT * FROM users--
1; DROP TABLE users--
admin'--
' OR 1=1--
```

#### Cross-Site Scripting (XSS)
```
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
<iframe src="javascript:alert(1)">
```

#### Path Traversal
```
../../../etc/passwd
..\\..\\..\\windows\\system32\\config\\sam
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
```

### Using cURL for Testing

```bash
# Test SQL Injection
curl "http://127.0.0.1:5000/api/users?id=' OR '1'='1"

# Test XSS
curl "http://127.0.0.1:5000/search?q=<script>alert(1)</script>"

# Test Path Traversal
curl "http://127.0.0.1:5000/files?file=../../../etc/passwd"

# Test POST form data
curl -X POST http://127.0.0.1:5000/contact \
  -d "name=<script>alert(1)</script>&email=test@test.com&message=test"
```

### Using Python Requests

```python
import requests

# Test SQL Injection
response = requests.get('http://127.0.0.1:5000/api/users?id=\' OR \'1\'=\'1')
print(f"Status: {response.status_code}")
print(f"Response: {response.json()}")

# Test XSS
response = requests.get('http://127.0.0.1:5000/search?q=<script>alert(1)</script>')
print(f"Status: {response.status_code}")

# Test Path Traversal
response = requests.get('http://127.0.0.1:5000/files?file=../../../etc/passwd')
print(f"Status: {response.status_code}")
```

## Expected Behavior

### ✅ Legitimate Requests
- Status Code: 200 OK
- Normal response with requested data

### ❌ Malicious Requests
- Status Code: 403 Forbidden
- JSON response with:
  ```json
  {
    "error": "Request blocked by WAF",
    "reason": "SQL Injection detected",
    "ip": "127.0.0.1"
  }
  ```

## Monitoring & Logs

- Check the `logs/` directory for WAF activity
- Logs include:
  - Blocked requests
  - Detection reasons
  - IP addresses
  - Timestamps

## Configuration

Modify WAF behavior by editing:
- `config/waf_config.yaml` - General settings
- `config/waf_rules.json` - Detection patterns
- `config/whitelist.json` - IP whitelist

## Rate Limiting Test

To test rate limiting, send multiple requests rapidly:

```bash
# Bash/PowerShell loop
for i in {1..100}; do curl http://127.0.0.1:5000/; done
```

After exceeding the rate limit, you should get a 403 response.

## Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'flask'"
**Solution**: Install dependencies with `pip install -r requirements.txt`

### Issue: Port 5000 already in use
**Solution**: Stop other applications using port 5000 or modify the port in `app.py`:
```python
app.run(debug=True, host='127.0.0.1', port=8080)
```

### Issue: WAF not blocking malicious requests
**Solution**: 
1. Check WAF configuration files
2. Verify detection patterns are enabled
3. Check logs for errors

## Features Demonstrated

1. ✅ SQL Injection Protection
2. ✅ XSS (Cross-Site Scripting) Prevention
3. ✅ Path Traversal Defense
4. ✅ Rate Limiting
5. ✅ IP Whitelist/Blacklist
6. ✅ Request Logging
7. ✅ Pattern Matching

## Security Notice

⚠️ **This is a test application only!** Do not deploy this to production or expose it to the internet. It contains intentionally vulnerable code for testing purposes.

## Next Steps

1. Run the application: `python app.py`
2. Open browser: http://127.0.0.1:5000
3. Click on "Test Payloads" for interactive testing
4. Monitor logs in the `logs/` directory
5. Adjust WAF configuration as needed

Happy testing! 🛡️
