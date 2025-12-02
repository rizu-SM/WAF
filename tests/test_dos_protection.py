# tests/test_dos_protection.py
"""
Test DoS protection (Rate Limiting + IP Auto-blocking)
Run: python tests/test_dos_protection.py
"""
import time
import sys
sys.path.insert(0, '.')

from src.core.waf import get_waf, WAFRequest


def test_rate_limiting():
    """Test that rate limiting blocks excessive requests"""
    print("=" * 60)
    print("🧪 Testing DoS Protection (Rate Limiting)")
    print("=" * 60)
    
    waf = get_waf()
    test_ip = "10.0.0.99"  # Test IP
    
    # Clear any previous state for this IP
    waf.rate_limiter.clear_ip(test_ip)
    if test_ip in waf.ip_manager.blocked_ips:
        waf.ip_manager.unblock_ip(test_ip)
    if test_ip in waf.ip_manager.violation_tracking:
        del waf.ip_manager.violation_tracking[test_ip]
    
    print(f"\n📋 Configuration:")
    print(f"   Rate limit: {waf.rate_limiter.requests_per_minute} requests/minute")
    print(f"   Block duration: {waf.rate_limiter.block_duration} seconds")
    print(f"   Auto-block threshold: {waf.ip_manager.block_threshold} violations")
    print(f"   Test IP: {test_ip}")
    
    # Simulate rapid requests
    print(f"\n🚀 Sending rapid requests from {test_ip}...")
    
    blocked_at = None
    for i in range(120):  # Try 120 requests
        request = WAFRequest(
            method="GET",
            path="/api/data",
            headers={"user-agent": "DoS-Test"},
            client_ip=test_ip,
            query_params={"page": str(i)}
        )
        
        response = waf.process_request(request)
        
        if not response.allowed:
            if blocked_at is None:
                blocked_at = i + 1
                print(f"\n🛑 BLOCKED at request #{blocked_at}")
                print(f"   Reason: {response.reason}")
                print(f"   Status: {response.status_code}")
            
            # Show first few blocked responses
            if i < blocked_at + 3:
                print(f"   Request #{i+1}: {response.reason}")
        else:
            if i % 20 == 0:
                print(f"   ✅ Request #{i+1}: allowed")
    
    # Check final state
    print(f"\n📊 Final State:")
    print(f"   Rate limiter blocked: {waf.rate_limiter.is_ip_blocked(test_ip)}")
    print(f"   IP Manager blocked: {waf.ip_manager.is_blocked(test_ip)}")
    
    reputation = waf.ip_manager.get_ip_reputation(test_ip)
    print(f"   Violations recorded: {reputation['violation_count']}")
    print(f"   Reputation score: {reputation['reputation_score']}")
    
    if waf.rate_limiter.is_ip_blocked(test_ip):
        remaining = waf.rate_limiter.get_block_remaining_time(test_ip)
        print(f"   Rate limit block remaining: {remaining:.1f}s")
    
    if waf.ip_manager.is_blocked(test_ip):
        remaining = waf.ip_manager.get_block_remaining_time(test_ip)
        print(f"   IP Manager block remaining: {remaining:.1f}s")
    
    # Stats
    print(f"\n📈 WAF Statistics:")
    stats = waf.get_statistics()
    print(f"   Total requests: {stats['total_requests']}")
    print(f"   Blocked: {stats['blocked_requests']}")
    print(f"   Block rate: {stats['block_rate']}%")
    
    print("\n" + "=" * 60)
    if blocked_at:
        print(f"✅ DoS Protection WORKING - Blocked after {blocked_at} requests")
    else:
        print("❌ DoS Protection NOT working - No requests blocked")
    print("=" * 60)
    
    return blocked_at is not None


def test_attack_violation_accumulation():
    """Test that attack attempts accumulate and trigger auto-block"""
    print("\n" + "=" * 60)
    print("🧪 Testing Attack Violation Auto-blocking")
    print("=" * 60)
    
    waf = get_waf()
    attacker_ip = "10.0.0.88"
    
    # Clear previous state
    waf.ip_manager.unblock_ip(attacker_ip)
    if attacker_ip in waf.ip_manager.violation_tracking:
        del waf.ip_manager.violation_tracking[attacker_ip]
    
    print(f"\n📋 Auto-block threshold: {waf.ip_manager.block_threshold} violations")
    print(f"   Attacker IP: {attacker_ip}")
    
    # Send attack requests (SQL injection attempts)
    attack_payloads = [
        "' OR 1=1--",
        "'; DROP TABLE users--",
        "1' UNION SELECT * FROM users--",
        "<script>alert('XSS')</script>",
        "../../etc/passwd",
        "' OR ''='",
        "<img src=x onerror=alert(1)>",
    ]
    
    print(f"\n🎯 Sending {len(attack_payloads)} attack attempts...")
    
    for i, payload in enumerate(attack_payloads):
        request = WAFRequest(
            method="GET",
            path="/search",
            headers={"user-agent": "Attacker"},
            client_ip=attacker_ip,
            query_params={"q": payload}
        )
        
        response = waf.process_request(request)
        reputation = waf.ip_manager.get_ip_reputation(attacker_ip)
        
        print(f"   Attack #{i+1}: {response.action} | Violations: {reputation['violation_count']} | Score: {reputation['reputation_score']}")
        
        if waf.ip_manager.is_blocked(attacker_ip):
            print(f"\n🛑 IP AUTO-BLOCKED after {i+1} attacks!")
            break
    
    # Final check
    print(f"\n📊 Final State:")
    print(f"   IP blocked: {waf.ip_manager.is_blocked(attacker_ip)}")
    
    if waf.ip_manager.is_blocked(attacker_ip):
        remaining = waf.ip_manager.get_block_remaining_time(attacker_ip)
        print(f"   Block remaining: {remaining:.1f}s")
    
    print("\n" + "=" * 60)
    if waf.ip_manager.is_blocked(attacker_ip):
        print("✅ Auto-blocking WORKING - Attacker IP blocked!")
    else:
        print("⚠️  Auto-blocking threshold not reached yet")
    print("=" * 60)


if __name__ == "__main__":
    print("\n🔒 WAF DoS Protection Test Suite\n")
    
    test_rate_limiting()
    test_attack_violation_accumulation()
    
    print("\n✅ All tests completed!")
