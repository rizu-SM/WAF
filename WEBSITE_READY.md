# 🎉 WAF Test Website - Successfully Created!

## ✅ What's Been Created

A fully functional test website has been created to test your WAF protection. The website is **currently running** at:

### 🌐 **http://127.0.0.1:5000**

## 📁 Files Created

### Main Application
- **`app.py`** - Flask web application with WAF integration
- **`test_waf_website.py`** - Automated testing script

### Templates (HTML Pages)
- `templates/base.html` - Base layout
- `templates/index.html` - Home page
- `templates/contact.html` - Contact form (XSS & SQL Injection tests)
- `templates/search.html` - Search page (XSS tests)
- `templates/test_payloads.html` - Interactive payload testing
- `templates/about.html` - About the WAF
- `templates/profile.html` - User profile page
- `templates/admin.html` - Admin dashboard
- `templates/403.html` - WAF blocked page
- `templates/404.html` - Not found page
- `templates/500.html` - Server error page

### Styling
- `static/css/style.css` - Modern, responsive CSS

### Documentation
- `TEST_WEBSITE.md` - Comprehensive testing guide
- `QUICKSTART.md` - Quick reference guide

### Batch Files (Windows)
- `start_website.bat` - Quick start the website
- `run_tests.bat` - Run automated tests

## 🚀 How to Use

### Currently Running
The website is **already running** in a background terminal. You can:
1. Click the browser preview that opened
2. Or open your browser manually to: http://127.0.0.1:5000

### Stop the Server
Press `Ctrl+C` in the terminal to stop it

### Restart Later
```bash
python app.py
```

Or double-click: `start_website.bat`

## 🧪 Testing the WAF

### Interactive Testing (Easiest)
1. Go to http://127.0.0.1:5000/test/payloads
2. Click the "Test" buttons to try various attacks
3. See real-time WAF blocking

### Manual Testing
Try these URLs in your browser:

**SQL Injection:**
```
http://127.0.0.1:5000/api/users?id=' OR '1'='1
```

**XSS Attack:**
```
http://127.0.0.1:5000/search?q=<script>alert(1)</script>
```

**Path Traversal:**
```
http://127.0.0.1:5000/files?file=../../../etc/passwd
```

### Automated Testing
In a **new terminal** (while the website runs):
```bash
python test_waf_website.py
```

Or double-click: `run_tests.bat`

## 📊 Expected Behavior

### ✅ Legitimate Requests
- Status: `200 OK`
- Normal response

### ❌ Malicious Requests (Should be blocked)
- Status: `403 Forbidden`
- Response:
```json
{
  "error": "Request blocked by WAF",
  "reason": "SQL Injection detected",
  "ip": "127.0.0.1"
}
```

## 📋 Available Test Endpoints

| Endpoint | Purpose | Test Type |
|----------|---------|-----------|
| `/` | Home page | General navigation |
| `/contact` | Contact form | XSS, SQL Injection |
| `/search` | Search page | XSS in query params |
| `/files` | File viewer | Path traversal |
| `/api/users` | API endpoint | SQL injection |
| `/user/<name>` | Profile page | XSS, path traversal |
| `/test/payloads` | Interactive testing | All attack types |
| `/waf/status` | WAF status | Monitor WAF |

## 🔍 Monitoring

### Check Logs
All WAF activity is logged to:
```
logs/waf.log
```

The logs include:
- Blocked requests
- Attack types detected
- IP addresses
- Timestamps
- Detection details

### Watch Logs in Real-Time (PowerShell)
```powershell
Get-Content logs/waf.log -Wait
```

## 🎯 Example Test Scenarios

### Scenario 1: Contact Form XSS
1. Go to http://127.0.0.1:5000/contact
2. Enter `<script>alert('XSS')</script>` in the name field
3. Submit the form
4. **Expected**: WAF blocks with 403 error

### Scenario 2: API SQL Injection
1. Go to http://127.0.0.1:5000/api/users?id=1 (should work)
2. Go to http://127.0.0.1:5000/api/users?id=' OR '1'='1 (should be blocked)
3. **Expected**: Second request blocked by WAF

### Scenario 3: Path Traversal
1. Go to http://127.0.0.1:5000/files?file=readme.txt (should work)
2. Go to http://127.0.0.1:5000/files?file=../../etc/passwd (should be blocked)
3. **Expected**: Second request blocked by WAF

## 📝 Sample Test Payloads

### SQL Injection
```
' OR '1'='1
' UNION SELECT * FROM users--
1; DROP TABLE users--
admin'--
```

### XSS (Cross-Site Scripting)
```
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
```

### Path Traversal
```
../../../etc/passwd
..\\..\\..\\windows\\system32\\config\\sam
....//....//etc/passwd
```

## 🛠️ Configuration

Modify WAF behavior by editing:
- `config/waf_config.yaml` - Main settings
- `config/waf_rules.json` - Detection rules
- `config/whitelist.json` - IP whitelist

## ⚙️ Features Implemented

✅ SQL Injection detection and blocking  
✅ XSS (Cross-Site Scripting) prevention  
✅ Path Traversal protection  
✅ Rate limiting (IP-based)  
✅ IP whitelist/blacklist  
✅ Comprehensive logging  
✅ Real-time threat detection  
✅ Interactive test interface  
✅ Automated testing script  

## 🚨 Security Warning

⚠️ **FOR TESTING ONLY!**

This application contains **intentionally vulnerable code** for testing purposes. 

**DO NOT:**
- Deploy to production
- Expose to the internet
- Use with real data

## 📚 Documentation

- **`TEST_WEBSITE.md`** - Full testing guide with detailed examples
- **`QUICKSTART.md`** - Quick reference card
- **`README.md`** - Main project documentation

## 💡 Tips

1. **Open Developer Console** (F12) to see network requests
2. **Check logs/** directory for WAF activity details
3. **Try the /test/payloads page** for easy interactive testing
4. **Use the automated script** for comprehensive testing

## 🎓 Next Steps

1. ✅ Website is running at http://127.0.0.1:5000
2. 🧪 Try the interactive payload testing at /test/payloads
3. 📊 Monitor logs/ directory for WAF activity
4. 🔧 Adjust WAF configuration as needed
5. 🚀 Run automated tests: `python test_waf_website.py`

## 🆘 Troubleshooting

**Issue**: Port 5000 already in use  
**Fix**: Edit `app.py` line 158 and change port to 8080

**Issue**: WAF not blocking  
**Fix**: Check `config/waf_config.yaml` - ensure `enabled: true`

**Issue**: Module not found  
**Fix**: Run `pip install -r requirements.txt`

---

**Happy Testing! 🛡️**

Your WAF protection system is now ready for comprehensive testing!
