# 🛡️ PyWAF — Python Web Application Firewall

A modular, Python-based **Web Application Firewall** built with Flask. PyWAF inspects every incoming HTTP request in real time and blocks common web attacks before they reach your application.

> ⚠️ The project ships with an **intentionally vulnerable** demo app so you can see the WAF in action. **Never** expose the demo app without WAF protection.

---

## ✨ Features

### 🔍 Attack Detection
| Engine | What it catches |
|---|---|
| **SQL Injection** | Keyword heuristics, logic manipulation (`' OR 1=1`), comment tokens (`--`, `/*`), and regex rule matching with confidence scoring (low / medium / high). |
| **XSS (Cross-Site Scripting)** | Dangerous HTML tags, event handlers (`onload`, `onerror`…), JavaScript URI schemes, encoded & obfuscated payloads. |
| **Path Traversal** | `../` sequences, null-byte injection, absolute-path access, encoding bypasses (`%2e%2e`), and dangerous system file checks (`/etc/passwd`, `win.ini`…). |

### 🔒 Security Controls
- **Rate Limiting** — Sliding-window algorithm tracks requests per IP; auto-blocks abusive clients for a configurable duration.
- **Brute-Force Protection** — Limits login attempts within a time window.
- **IP Management** — Block / unblock IPs (temporary or permanent), maintain a whitelist, track violations with auto-blocking, and persist state to disk.

### 📊 Monitoring & Logging
- **WAF Statistics Dashboard** — Real-time stats page at `/waf/stats` showing total requests, blocked attacks, and recent security events.
- **REST API** — `GET /api/waf/stats` for programmatic access; `POST /api/waf/reload` to hot-reload configuration.
- **Structured Logging** — All decisions (allow / block / challenge) are logged with attack type, confidence level, and request details.

### ⚙️ Configuration
- **YAML config** (`config/waf_config.yaml`) — Enable/disable detectors, set rate limits, choose WAF mode (`block` / `monitor`).
- **JSON rules** (`config/waf_rules.json`) — Regex patterns for SQL injection, XSS, and path traversal.
- **Whitelist** (`config/whitelist.json`) — Trusted IPs that bypass all checks.
- **Hot-reload** — Update rules without restarting the server via the reload API endpoint.

---

## 🏗️ Project Structure

```
PyWAF/
├── app.py                  # Flask demo app + WAF middleware
├── config/
│   ├── waf_config.yaml     # Main WAF settings
│   ├── waf_rules.json      # Detection regex patterns
│   ├── whitelist.json       # Whitelisted IPs
│   └── blocked_ips.json     # Persisted blocked IPs
├── src/
│   ├── core/
│   │   ├── waf.py           # Main WAF engine (PyWAF class)
│   │   └── config_loader.py # YAML/JSON config loading
│   ├── detection/
│   │   ├── sql_injection.py # SQL injection detector
│   │   ├── xss.py           # XSS detector
│   │   ├── path_traversal.py# Path traversal detector
│   │   └── pattern_matcher.py # Shared regex helper
│   ├── security/
│   │   ├── rate_limiter.py  # Sliding-window rate limiter
│   │   └── ip_manager.py    # IP blocking & whitelisting
│   ├── middleware/
│   │   └── request_parser.py# Flask ↔ WAF request adapter
│   └── utils/
│       └── logger.py        # Structured WAF logger
├── templates/               # HTML pages (dashboard, login, search…)
├── tests/                   # Unit tests for each detector & module
├── docs/                    # Design docs & detection flow notes
└── logs/                    # Runtime log files
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/PyWAF.git
cd PyWAF

# Install dependencies
pip install -r requirements.txt
```

### Run

```bash
python app.py
```

The server starts on **http://localhost:5000**.

| Page | URL |
|---|---|
| Home | `http://localhost:5000/` |
| WAF Dashboard | `http://localhost:5000/waf/stats` |
| Login (SQLi demo) | `http://localhost:5000/login` |
| Search (XSS demo) | `http://localhost:5000/search` |
| File Viewer (Path Traversal demo) | `http://localhost:5000/files` |

**Demo credentials:** `admin / admin123` or `john / password`

---

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/

# Run a specific detector test
python -m pytest tests/test_sql_inj.py
python -m pytest tests/test_xss.py
python -m pytest tests/test_path_traversal.py
python -m pytest tests/test_dos_protection.py
```

---

## 🧰 Tech Stack

- **Python 3** + **Flask** — Web framework & middleware
- **SQLite** — Demo database
- **PyYAML** — Configuration parsing
- **Regex** — Pattern-based detection engine
- **Threading** — Thread-safe rate limiting & IP management

---
