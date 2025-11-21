# WAF Test Website - Quick Reference

## 🚀 Quick Start

### Option 1: Using Batch File (Easiest - Windows)
```bash
# Double-click this file or run in terminal:
start_website.bat
```

### Option 2: Manual Start
```bash
# Install dependencies
pip install -r requirements.txt

# Run the website
python app.py
```

## 🌐 Access the Website

Open your browser and go to: **http://127.0.0.1:5000**

## 🧪 Running Automated Tests

### Option 1: Using Batch File
```bash
# First, start the website (in another terminal)
start_website.bat

# Then run tests (in a new terminal)
run_tests.bat
```

### Option 2: Manual Testing
```bash
python test_waf_website.py
```

## 📋 What's Included

### Web Pages
- **/** - Home page with overview
- **/contact** - Contact form (test XSS & SQL injection)
- **/search** - Search page (test XSS)
- **/files** - File viewer (test path traversal)
- **/api/users** - API endpoint (test SQL injection)
- **/test/payloads** - Interactive testing page
- **/about** - About the WAF
- **/waf/status** - WAF status check

### Files Created
```
├── app.py                    # Main Flask application
├── test_waf_website.py       # Automated test script
├── start_website.bat         # Quick start script
├── run_tests.bat             # Quick test runner
├── TEST_WEBSITE.md           # Detailed documentation
├── templates/                # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── contact.html
│   ├── search.html
│   ├── test_payloads.html
│   ├── about.html
│   ├── profile.html
│   ├── admin.html
│   ├── 403.html
│   ├── 404.html
│   └── 500.html
└── static/                   # CSS styles
    └── css/
        └── style.css
```

## 🎯 Quick Test Examples

### Test SQL Injection
```
http://127.0.0.1:5000/api/users?id=' OR '1'='1
```

### Test XSS
```
http://127.0.0.1:5000/search?q=<script>alert(1)</script>
```

### Test Path Traversal
```
http://127.0.0.1:5000/files?file=../../../etc/passwd
```

## ✅ Expected Results

- **Malicious requests**: Should return `403 Forbidden` with WAF block message
- **Legitimate requests**: Should return `200 OK` with normal content

## 📊 Monitoring

- Check `logs/` directory for WAF activity
- All blocked requests are logged with details

## 🛠️ Troubleshooting

**Port 5000 in use?**
- Edit `app.py` and change the port number

**WAF not blocking?**
- Check `config/waf_config.yaml`
- Verify detection patterns in `config/waf_rules.json`

**Dependencies missing?**
- Run: `pip install -r requirements.txt`

## 📖 Full Documentation

See `TEST_WEBSITE.md` for comprehensive testing guide and examples.

---

**Security Notice**: This is for testing only. Do not expose to the internet!
