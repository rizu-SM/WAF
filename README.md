# PyWAF - Python Web Application Firewall

A comprehensive Web Application Firewall (WAF) implemented in Python with Flask integration.

## 🛡️ Features

### Security Protection
- **SQL Injection Detection** - Advanced pattern matching with keyword, logic, and regex detection
- **XSS Prevention** - Detects script tags, event handlers, URI schemes, and obfuscation techniques
- **Path Traversal Defense** - Blocks directory traversal, null bytes, and encoding bypasses
- **Rate Limiting** - Sliding window algorithm with configurable limits
- **IP Management** - Automatic blocking with violation tracking and whitelisting

### Configuration
- **Flexible Modes** - Block, Log, or Challenge mode
- **YAML Configuration** - Easy-to-edit configuration files
- **JSON Rules** - Regex pattern rules for all attack types
- **Whitelist Support** - IP and path whitelisting

### Monitoring
- **Real-time Statistics** - Dashboard with attack metrics
- **Event Logging** - Structured JSON logging with rotation
- **Health Checks** - Monitor WAF status and configuration

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the Vulnerable Web Application

```bash
python app.py
```

The application will start on `http://localhost:5000`

### 3. Access the Application

- **Home Page**: http://localhost:5000/
- **WAF Dashboard**: http://localhost:5000/waf/stats
- **Login Page**: http://localhost:5000/login

### 4. Test Credentials

```
Username: admin | Password: admin123
Username: john  | Password: password
```

## 🧪 Testing the WAF

### SQL Injection Tests

Try logging in with these payloads (all will be blocked):

```
Username: admin' OR '1'='1'--
Username: ' OR 1=1--
Username: admin'--
```

### XSS Tests

Try searching with these payloads (all will be blocked):

```
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert('XSS')>
javascript:alert('XSS')
```

### Path Traversal Tests

Try accessing files with these paths (all will be blocked):

```
../../etc/passwd
..\\..\\windows\\system32\\config\\sam
%2e%2e%2f%2e%2e%2fetc%2fpasswd
/etc/shadow
```

## ⚠️ Security Notice

**IMPORTANT**: The included web application (`app.py`) contains **intentional security vulnerabilities** for testing purposes. 

- **DO NOT** use this application in production
- **DO NOT** expose it to the internet
- This is for **educational and testing purposes only**

The PyWAF protects against these attacks, demonstrating how a WAF works in real-time.
