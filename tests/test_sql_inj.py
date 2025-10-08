import sys
import os

# Add project root to Python path - THIS FIXES THE IMPORT
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Now import your detection function
from src.detection.sql_injection import detect_sql_injection

# Test Case 1: Clean Request (Should be safe)
clean_request = {
    "path": "/search",
    "args": {"q": "python programming"},
    "body": "",
    "headers": {
        "user-agent": "Mozilla/5.0",
        "referer": "https://google.com"
    }
}

# Test Case 2: SQL Injection Attack (Should be detected)
sql_injection_request = {
    "path": "/login",
    "args": {"user": "admin' OR '1'='1'--", "password": "123"},
    "body": "",
    "headers": {
        "user-agent": "Mozilla/5.0",
        "cookie": "session=abc123"
    }
}

# Test Case 3: Multiple Indicators (Should be detected)
multi_attack_request = {
    "path": "/users",
    "args": {"id": "1 UNION SELECT 1,2,3"},
    "body": "",
    "headers": {
        "user-agent": "Mozilla/5.0"
    }
}

# Run tests
print("=== TEST 1: Clean Request ===")
is_attack, details = detect_sql_injection(clean_request)
print(f"Attack detected: {is_attack}")
print(f"Details: {details}\n")

print("=== TEST 2: SQL Injection ===")
is_attack, details = detect_sql_injection(sql_injection_request)
print(f"Attack detected: {is_attack}")
print(f"Details: {details}\n")

print("=== TEST 3: Multiple Indicators ===")
is_attack, details = detect_sql_injection(multi_attack_request)
print(f"Attack detected: {is_attack}")
print(f"Details: {details}\n")