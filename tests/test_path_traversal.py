import sys
import os

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detection.path_traversal import detect_path_traversal

print("=" * 70)
print("PATH TRAVERSAL DETECTION TEST SUITE")
print("=" * 70)

# Test Case 1: Clean Request (Should be safe)
print("\n[TEST 1] Clean Request - Should PASS")
clean_request = {
    "path": "/api/files/document.pdf",
    "args": {"id": "12345", "type": "pdf"},
    "body": "",
    "headers": {
        "user-agent": "Mozilla/5.0",
        "referer": "https://example.com"
    }
}

is_attack, details = detect_path_traversal(clean_request)
print(f"  Attack detected: {is_attack}")
print(f"  Details: {details}")
assert not is_attack, "Clean request should not be detected as path traversal"
print("  ✅ PASSED")

# Test Case 2: Basic Directory Traversal (../)
print("\n[TEST 2] Basic Directory Traversal (../) - Should BLOCK")
basic_traversal = {
    "path": "/files",
    "args": {"file": "../../etc/passwd"},
    "body": "",
    "headers": {"user-agent": "Mozilla/5.0"}
}

is_attack, details = detect_path_traversal(basic_traversal)
print(f"  Attack detected: {is_attack}")
print(f"  Confidence: {details.get('confidence', 'N/A')}")
print(f"  Reason: {details.get('reason', 'N/A')}")
assert is_attack, "Basic traversal should be detected"
assert details.get('confidence') == 'high', "Should be high confidence"
print("  ✅ PASSED")

# Test Case 3: Windows Path Traversal (..\\)
print("\n[TEST 3] Windows Path Traversal (..\\\\ ) - Should BLOCK")
windows_traversal = {
    "path": "/download",
    "args": {"file": "..\\..\\windows\\system32\\config\\sam"},
    "body": "",
    "headers": {"user-agent": "Mozilla/5.0"}
}

is_attack, details = detect_path_traversal(windows_traversal)
print(f"  Attack detected: {is_attack}")
print(f"  Confidence: {details.get('confidence', 'N/A')}")
assert is_attack, "Windows traversal should be detected"
assert details.get('confidence') == 'high', "Should be high confidence"
print("  ✅ PASSED")

# Test Case 4: URL Encoded Traversal
print("\n[TEST 4] URL Encoded Traversal - Should BLOCK")
encoded_traversal = {
    "path": "/files",
    "args": {"path": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
    "body": "",
    "headers": {"user-agent": "Mozilla/5.0"}
}

is_attack, details = detect_path_traversal(encoded_traversal)
print(f"  Attack detected: {is_attack}")
print(f"  Confidence: {details.get('confidence', 'N/A')}")
assert is_attack, "URL encoded traversal should be detected"
assert details.get('confidence') == 'high', "Should be high confidence"
print("  ✅ PASSED")

# Test Case 5: Null Byte Injection
print("\n[TEST 5] Null Byte Injection - Should BLOCK")
null_byte = {
    "path": "/view",
    "args": {"file": "../../etc/passwd%00.jpg"},
    "body": "",
    "headers": {"user-agent": "Mozilla/5.0"}
}

is_attack, details = detect_path_traversal(null_byte)
print(f"  Attack detected: {is_attack}")
print(f"  Confidence: {details.get('confidence', 'N/A')}")
assert is_attack, "Null byte injection should be detected"
assert details.get('confidence') == 'high', "Should be high confidence"
print("  ✅ PASSED")

# Test Case 6: Absolute Path Access (/etc/passwd)
print("\n[TEST 6] Absolute Path Access - Should BLOCK")
absolute_path = {
    "path": "/files",
    "args": {"file": "/etc/passwd"},
    "body": "",
    "headers": {"user-agent": "Mozilla/5.0"}
}

is_attack, details = detect_path_traversal(absolute_path)
print(f"  Attack detected: {is_attack}")
print(f"  Confidence: {details.get('confidence', 'N/A')}")
assert is_attack, "Absolute path should be detected"
assert details.get('confidence') == 'high', "Should be high confidence"
print("  ✅ PASSED")

# Test Case 7: Double URL Encoding
print("\n[TEST 7] Double URL Encoding - Should BLOCK")
double_encoded = {
    "path": "/download",
    "args": {"file": "%252e%252e%252f%252e%252e%252fetc%252fpasswd"},
    "body": "",
    "headers": {"user-agent": "Mozilla/5.0"}
}

is_attack, details = detect_path_traversal(double_encoded)
print(f"  Attack detected: {is_attack}")
print(f"  Confidence: {details.get('confidence', 'N/A')}")
assert is_attack, "Double encoded traversal should be detected"
assert details.get('confidence') == 'high', "Should be high confidence"
print("  ✅ PASSED")

# Test Case 8: Excessive Directory Traversal
print("\n[TEST 8] Excessive Directory Traversal - Should BLOCK")
excessive = {
    "path": "/files",
    "args": {"path": "../../../../../../../../../etc/passwd"},
    "body": "",
    "headers": {"user-agent": "Mozilla/5.0"}
}

is_attack, details = detect_path_traversal(excessive)
print(f"  Attack detected: {is_attack}")
print(f"  Confidence: {details.get('confidence', 'N/A')}")
assert is_attack, "Excessive traversal should be detected"
print("  ✅ PASSED")

# Test Case 9: Windows System Path
print("\n[TEST 9] Windows System Path - Should BLOCK")
windows_system = {
    "path": "/files",
    "args": {"file": "c:\\windows\\system32\\config\\sam"},
    "body": "",
    "headers": {"user-agent": "Mozilla/5.0"}
}

is_attack, details = detect_path_traversal(windows_system)
print(f"  Attack detected: {is_attack}")
print(f"  Confidence: {details.get('confidence', 'N/A')}")
assert is_attack, "Windows system path should be detected"
print("  ✅ PASSED")

# Test Case 10: /etc/shadow Access
print("\n[TEST 10] /etc/shadow Access - Should BLOCK")
shadow_file = {
    "path": "/download",
    "args": {"file": "../../../etc/shadow"},
    "body": "",
    "headers": {"user-agent": "Mozilla/5.0"}
}

is_attack, details = detect_path_traversal(shadow_file)
print(f"  Attack detected: {is_attack}")
print(f"  Confidence: {details.get('confidence', 'N/A')}")
assert is_attack, "/etc/shadow access should be detected"
print("  ✅ PASSED")

# Test Case 11: Mixed Separators
print("\n[TEST 11] Mixed Path Separators - Should BLOCK")
mixed_separators = {
    "path": "/view",
    "args": {"file": "..\\../etc/passwd"},
    "body": "",
    "headers": {"user-agent": "Mozilla/5.0"}
}

is_attack, details = detect_path_traversal(mixed_separators)
print(f"  Attack detected: {is_attack}")
print(f"  Confidence: {details.get('confidence', 'N/A')}")
assert is_attack, "Mixed separators should be detected"
print("  ✅ PASSED")

# Test Case 12: Boot.ini Access (Windows)
print("\n[TEST 12] boot.ini Access - Should BLOCK")
boot_ini = {
    "path": "/files",
    "args": {"file": "../../boot.ini"},
    "body": "",
    "headers": {"user-agent": "Mozilla/5.0"}
}

is_attack, details = detect_path_traversal(boot_ini)
print(f"  Attack detected: {is_attack}")
print(f"  Confidence: {details.get('confidence', 'N/A')}")
assert is_attack, "boot.ini access should be detected"
print("  ✅ PASSED")

# Test Case 13: Legitimate Deep Path (Should be safe if no traversal)
print("\n[TEST 13] Legitimate Deep Path - Should PASS")
legitimate_deep = {
    "path": "/api/v1/users/documents/reports/2024/november/report.pdf",
    "args": {"download": "true"},
    "body": "",
    "headers": {"user-agent": "Mozilla/5.0"}
}

is_attack, details = detect_path_traversal(legitimate_deep)
print(f"  Attack detected: {is_attack}")
print(f"  Details: {details}")
# This might trigger path depth warning but shouldn't be high confidence block
if is_attack:
    assert details.get('confidence') != 'high', "Legitimate deep path should not be high confidence block"
    print("  ⚠️  PASSED (low/medium confidence detection)")
else:
    print("  ✅ PASSED")

print("\n" + "=" * 70)
print("ALL CRITICAL TESTS PASSED! ✅")
print("=" * 70)
print(f"\nTotal tests run: 13")
print("Path traversal detection engine is working correctly!")
