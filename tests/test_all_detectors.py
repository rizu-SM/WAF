"""
Comprehensive WAF Integration Test - SQL Injection + XSS + Path Traversal
Tests all three detection engines working together
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.waf import get_waf, WAFRequest

print("=" * 80)
print("COMPREHENSIVE WAF TEST - SQL INJECTION + XSS + PATH TRAVERSAL")
print("=" * 80)

waf = get_waf()

test_cases = [
    {
        "name": "Clean Request",
        "request": WAFRequest(
            method="GET",
            path="/api/users",
            headers={"user-agent": "Mozilla/5.0"},
            client_ip="192.168.1.100",
            query_params={"page": "1", "limit": "10"}
        ),
        "expected": "allow",
        "attack_type": None
    },
    {
        "name": "SQL Injection - Classic OR 1=1",
        "request": WAFRequest(
            method="POST",
            path="/login",
            headers={"user-agent": "Mozilla/5.0", "content-type": "application/json"},
            client_ip="192.168.1.101",
            body='{"username": "admin\' OR \'1\'=\'1\'--", "password": "test"}'
        ),
        "expected": "block",
        "attack_type": "sql_injection"
    },
    {
        "name": "SQL Injection - UNION SELECT",
        "request": WAFRequest(
            method="GET",
            path="/product",
            headers={"user-agent": "Mozilla/5.0"},
            client_ip="192.168.1.102",
            query_params={"id": "1 UNION SELECT username,password FROM users"}
        ),
        "expected": "block",
        "attack_type": "sql_injection"
    },
    {
        "name": "XSS - Script Tag",
        "request": WAFRequest(
            method="GET",
            path="/search",
            headers={"user-agent": "Mozilla/5.0"},
            client_ip="192.168.1.103",
            query_params={"q": "<script>alert('XSS')</script>"}
        ),
        "expected": "block",
        "attack_type": "xss"
    },
    {
        "name": "XSS - Event Handler (onerror)",
        "request": WAFRequest(
            method="POST",
            path="/comment",
            headers={"user-agent": "Mozilla/5.0"},
            client_ip="192.168.1.104",
            body="comment=<img src=x onerror=alert(document.cookie)>"
        ),
        "expected": "block",
        "attack_type": "xss"
    },
    {
        "name": "XSS - JavaScript URI",
        "request": WAFRequest(
            method="GET",
            path="/redirect",
            headers={"user-agent": "Mozilla/5.0"},
            client_ip="192.168.1.105",
            query_params={"url": "javascript:void(document.location='http://evil.com')"}
        ),
        "expected": "block",
        "attack_type": "xss"
    },
    {
        "name": "Path Traversal - Unix Style (../../etc/passwd)",
        "request": WAFRequest(
            method="GET",
            path="/files",
            headers={"user-agent": "Mozilla/5.0"},
            client_ip="192.168.1.106",
            query_params={"file": "../../etc/passwd"}
        ),
        "expected": "block",
        "attack_type": "path_traversal"
    },
    {
        "name": "Path Traversal - Windows Style (..\\..\\windows)",
        "request": WAFRequest(
            method="GET",
            path="/download",
            headers={"user-agent": "Mozilla/5.0"},
            client_ip="192.168.1.107",
            query_params={"file": "..\\..\\windows\\system32\\config\\sam"}
        ),
        "expected": "block",
        "attack_type": "path_traversal"
    },
    {
        "name": "Path Traversal - URL Encoded",
        "request": WAFRequest(
            method="GET",
            path="/view",
            headers={"user-agent": "Mozilla/5.0"},
            client_ip="192.168.1.108",
            query_params={"path": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"}
        ),
        "expected": "block",
        "attack_type": "path_traversal"
    },
    {
        "name": "Path Traversal - Null Byte Injection",
        "request": WAFRequest(
            method="GET",
            path="/files",
            headers={"user-agent": "Mozilla/5.0"},
            client_ip="192.168.1.109",
            query_params={"file": "../../etc/passwd%00.jpg"}
        ),
        "expected": "block",
        "attack_type": "path_traversal"
    },
    {
        "name": "Combined Attack - SQL + Path Traversal",
        "request": WAFRequest(
            method="GET",
            path="/search",
            headers={"user-agent": "Mozilla/5.0"},
            client_ip="192.168.1.110",
            query_params={"q": "' OR 1=1-- AND file=../../etc/passwd"}
        ),
        "expected": "block",
        "attack_type": "sql_injection"  # First detector wins
    },
    {
        "name": "Combined Attack - XSS + Path Traversal",
        "request": WAFRequest(
            method="GET",
            path="/view",
            headers={"user-agent": "Mozilla/5.0"},
            client_ip="192.168.1.111",
            query_params={"file": "../config.php", "msg": "<script>alert(1)</script>"}
        ),
        "expected": "block",
        "attack_type": "path_traversal"  # First detector wins
    },
    {
        "name": "Whitelisted IP (Bypass All Checks)",
        "request": WAFRequest(
            method="GET",
            path="/admin",
            headers={"user-agent": "curl/7.0"},
            client_ip="127.0.0.1",
            query_params={"action": "' DROP TABLE users--"}
        ),
        "expected": "allow",
        "attack_type": None
    },
]

passed = 0
failed = 0
results_by_type = {"sql_injection": 0, "xss": 0, "path_traversal": 0}

for i, test in enumerate(test_cases, 1):
    print(f"\n[TEST {i}] {test['name']}")
    print(f"  IP: {test['request'].client_ip}")
    print(f"  Path: {test['request'].path}")
    
    result = waf.process_request(test['request'])
    
    print(f"  Result: {result.action} - {result.reason}")
    print(f"  Allowed: {result.allowed}")
    
    detected_type = result.details.get('attack_type')
    if detected_type:
        print(f"  Attack Type: {detected_type}")
        print(f"  Confidence: {result.confidence}")
        results_by_type[detected_type] = results_by_type.get(detected_type, 0) + 1
    
    # Verify expectation
    actual = "allow" if result.allowed else "block"
    if actual == test['expected']:
        print(f"  ✅ PASSED (expected: {test['expected']})")
        passed += 1
    else:
        print(f"  ❌ FAILED (expected: {test['expected']}, got: {actual})")
        failed += 1

# Summary
print("\n" + "=" * 80)
print("TEST SUMMARY")
print("=" * 80)
print(f"Total Tests: {len(test_cases)}")
print(f"Passed: {passed} ✅")
print(f"Failed: {failed} ❌")
print(f"Success Rate: {(passed/len(test_cases)*100):.1f}%")

# WAF Statistics
print("\n" + "=" * 80)
print("WAF STATISTICS")
print("=" * 80)
stats = waf.get_statistics()
print(f"Total Requests Processed: {stats['total_requests']}")
print(f"Blocked: {stats['blocked_requests']}")
print(f"Allowed: {stats['allowed_requests']}")
print(f"Block Rate: {stats['block_rate']}%")

if stats['by_attack_type']:
    print("\nAttacks Detected by Type:")
    for attack_type, counts in stats['by_attack_type'].items():
        print(f"  {attack_type.upper().replace('_', ' ')}:")
        print(f"    Detected: {counts['detected']}")
        print(f"    Blocked: {counts['blocked']}")
        print(f"    Logged: {counts['logged']}")

# Health Check
print("\n" + "=" * 80)
print("WAF HEALTH CHECK")
print("=" * 80)
health = waf.health_check()
print(f"Status: {health['status'].upper()}")
print(f"Mode: {health['mode']}")
print(f"Total Detection Patterns: {health['total_patterns']}")
print(f"\nDetection Engines:")
for detector, enabled in health['detectors_enabled'].items():
    status = "✓ ENABLED" if enabled else "✗ DISABLED"
    detector_name = detector.replace('_', ' ').title()
    print(f"  {status:12} - {detector_name}")

print(f"\nWhitelist Configuration:")
print(f"  Whitelisted IPs: {health['whitelisted_ips']}")
print(f"  Whitelisted Paths: {health['whitelisted_paths']}")

print("\n" + "=" * 80)
if failed == 0:
    print("🎉 ALL TESTS PASSED! WAF IS FULLY OPERATIONAL!")
    print("   ✓ SQL Injection Detection")
    print("   ✓ XSS Detection")
    print("   ✓ Path Traversal Detection")
else:
    print(f"⚠️  {failed} TEST(S) FAILED - REVIEW REQUIRED")
print("=" * 80)
