"""
Automated WAF Testing Script
Tests various attack vectors against the test website
"""

import requests
import time
from colorama import init, Fore, Style

# Initialize colorama for colored output
init()

BASE_URL = "http://127.0.0.1:5000"

# Test payloads
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT * FROM users--",
    "1; DROP TABLE users--",
    "admin'--",
    "' OR 1=1--",
    "1' AND '1'='1",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src='javascript:alert(1)'>",
    "<body onload=alert(1)>",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "../../../../../../etc/passwd",
]


def print_header(text):
    """Print a formatted header"""
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{text:^70}")
    print(f"{'=' * 70}{Style.RESET_ALL}\n")


def print_result(test_name, blocked, reason=""):
    """Print test result"""
    if blocked:
        print(f"{Fore.GREEN}✓ BLOCKED{Style.RESET_ALL} - {test_name}")
        if reason:
            print(f"  Reason: {reason}")
    else:
        print(f"{Fore.RED}✗ ALLOWED{Style.RESET_ALL} - {test_name} (Potential bypass!)")


def test_sql_injection():
    """Test SQL Injection protection"""
    print_header("SQL INJECTION TESTS")
    
    for payload in SQL_INJECTION_PAYLOADS:
        try:
            # Test in query parameter
            response = requests.get(f"{BASE_URL}/api/users?id={payload}", timeout=5)
            blocked = response.status_code == 403
            reason = response.json().get('reason', '') if blocked else ''
            print_result(f"SQL in query: {payload[:30]}", blocked, reason)
            time.sleep(0.1)
            
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ ERROR{Style.RESET_ALL} - {payload[:30]}: {str(e)}")


def test_xss():
    """Test XSS protection"""
    print_header("CROSS-SITE SCRIPTING (XSS) TESTS")
    
    for payload in XSS_PAYLOADS:
        try:
            # Test in query parameter
            response = requests.get(f"{BASE_URL}/search?q={payload}", timeout=5)
            blocked = response.status_code == 403
            reason = response.json().get('reason', '') if blocked else ''
            print_result(f"XSS in query: {payload[:40]}", blocked, reason)
            time.sleep(0.1)
            
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ ERROR{Style.RESET_ALL} - {payload[:40]}: {str(e)}")


def test_path_traversal():
    """Test Path Traversal protection"""
    print_header("PATH TRAVERSAL TESTS")
    
    for payload in PATH_TRAVERSAL_PAYLOADS:
        try:
            # Test in file parameter
            response = requests.get(f"{BASE_URL}/files?file={payload}", timeout=5)
            blocked = response.status_code == 403
            reason = response.json().get('reason', '') if blocked else ''
            print_result(f"Path traversal: {payload[:40]}", blocked, reason)
            time.sleep(0.1)
            
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ ERROR{Style.RESET_ALL} - {payload[:40]}: {str(e)}")


def test_form_post():
    """Test POST form data"""
    print_header("POST FORM DATA TESTS")
    
    try:
        # Test XSS in form
        response = requests.post(f"{BASE_URL}/contact", data={
            'name': '<script>alert(1)</script>',
            'email': 'test@test.com',
            'message': 'Test message'
        }, timeout=5)
        blocked = response.status_code == 403
        reason = response.json().get('reason', '') if blocked else ''
        print_result("XSS in POST form", blocked, reason)
        
        time.sleep(0.1)
        
        # Test SQL in form
        response = requests.post(f"{BASE_URL}/contact", data={
            'name': "' OR '1'='1",
            'email': 'test@test.com',
            'message': 'Test message'
        }, timeout=5)
        blocked = response.status_code == 403
        reason = response.json().get('reason', '') if blocked else ''
        print_result("SQL injection in POST form", blocked, reason)
        
    except Exception as e:
        print(f"{Fore.YELLOW}⚠ ERROR{Style.RESET_ALL} - POST test: {str(e)}")


def test_rate_limiting():
    """Test rate limiting"""
    print_header("RATE LIMITING TEST")
    
    print("Sending 50 rapid requests...")
    blocked_count = 0
    
    try:
        for i in range(50):
            response = requests.get(f"{BASE_URL}/", timeout=5)
            if response.status_code == 403:
                blocked_count += 1
            time.sleep(0.05)  # Small delay
        
        if blocked_count > 0:
            print(f"{Fore.GREEN}✓ RATE LIMITING ACTIVE{Style.RESET_ALL}")
            print(f"  Blocked {blocked_count}/50 requests")
        else:
            print(f"{Fore.YELLOW}⚠ RATE LIMITING NOT TRIGGERED{Style.RESET_ALL}")
            print(f"  Note: This may be expected depending on your rate limit configuration")
            
    except Exception as e:
        print(f"{Fore.YELLOW}⚠ ERROR{Style.RESET_ALL} - Rate limiting test: {str(e)}")


def test_legitimate_requests():
    """Test that legitimate requests are allowed"""
    print_header("LEGITIMATE REQUEST TESTS")
    
    legitimate_tests = [
        (f"{BASE_URL}/", "Home page"),
        (f"{BASE_URL}/about", "About page"),
        (f"{BASE_URL}/search?q=hello", "Normal search"),
        (f"{BASE_URL}/api/users?id=1", "API with valid ID"),
        (f"{BASE_URL}/files?file=readme.txt", "File request"),
    ]
    
    for url, description in legitimate_tests:
        try:
            response = requests.get(url, timeout=5)
            allowed = response.status_code == 200
            
            if allowed:
                print(f"{Fore.GREEN}✓ ALLOWED{Style.RESET_ALL} - {description}")
            else:
                print(f"{Fore.RED}✗ BLOCKED{Style.RESET_ALL} - {description} (False positive!)")
            
            time.sleep(0.1)
            
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ ERROR{Style.RESET_ALL} - {description}: {str(e)}")


def check_server():
    """Check if the server is running"""
    try:
        response = requests.get(BASE_URL, timeout=5)
        return True
    except:
        return False


def main():
    """Main test runner"""
    print(f"{Fore.MAGENTA}")
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║              WAF AUTOMATED TESTING SCRIPT                          ║")
    print("║              Testing against http://127.0.0.1:5000                 ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print(f"{Style.RESET_ALL}")
    
    # Check if server is running
    if not check_server():
        print(f"{Fore.RED}✗ ERROR: Server is not running at {BASE_URL}")
        print(f"{Style.RESET_ALL}Please start the server with: python app.py")
        return
    
    print(f"{Fore.GREEN}✓ Server is running{Style.RESET_ALL}\n")
    
    # Run tests
    try:
        test_legitimate_requests()
        test_sql_injection()
        test_xss()
        test_path_traversal()
        test_form_post()
        test_rate_limiting()
        
        # Summary
        print_header("TEST SUMMARY")
        print(f"All tests completed!")
        print(f"Check the logs directory for detailed WAF activity.")
        print(f"\n{Fore.GREEN}✓ = Request blocked by WAF (Expected)")
        print(f"{Fore.RED}✗ = Request allowed (Potential issue)")
        print(f"{Fore.YELLOW}⚠ = Error or warning{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Tests interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Unexpected error: {str(e)}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
