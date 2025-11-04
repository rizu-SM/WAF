# src/security/rate_limiter.py
import time
import logging
from typing import Dict, Tuple, Optional, List
from collections import defaultdict
from threading import Lock

class RateLimiter:
    """
    Rate limiting implementation with sliding window algorithm
    Tracks requests per IP and applies limits with thread safety
    """
    
    def __init__(self, requests_per_minute: int = 100, block_duration: int = 300):
        self.requests_per_minute = requests_per_minute
        self.block_duration = block_duration
        self.logger = logging.getLogger(__name__)
        
        # Storage for request timestamps and blocked IPs
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self.blocked_ips: Dict[str, float] = {}  # IP -> block start time
        
        # Thread safety
        self.lock = Lock()
        
        # Cleanup tracking
        self.last_cleanup = time.time()
        self.cleanup_interval = 600  # Clean every 10 minutes
        
        self.logger.info(f"Rate limiter initialized: {requests_per_minute} req/min, {block_duration}s block")
    
    def rate_limit_check(self, client_ip: str) -> Tuple[bool, Optional[str]]:
        """
        Check if IP is rate limited using sliding window algorithm
        
        Args:
            client_ip: Client IP address
            
        Returns:
            Tuple of (is_blocked: bool, reason: str or None)
        """
        current_time = time.time()
        
        with self.lock:
            # Periodic cleanup
            if current_time - self.last_cleanup > self.cleanup_interval:
                self._cleanup_old_data(current_time)
                self.last_cleanup = current_time
            
            # Check if IP is temporarily blocked
            if self._is_ip_blocked(client_ip, current_time):
                remaining_time = self._get_block_remaining_time(client_ip, current_time)
                self.logger.warning(f"Rate limit blocked IP {client_ip} ({remaining_time}s remaining)")
                return True, f"rate_limit_blocked:{int(remaining_time)}s"
            
            # Clean old requests for this IP (older than 1 minute)
            self._clean_old_requests(client_ip, current_time)
            
            # Check if over limit
            request_count = len(self.requests[client_ip])
            if request_count >= self.requests_per_minute:
                self._block_ip(client_ip, current_time)
                self.logger.warning(f"Rate limit exceeded for IP {client_ip} ({request_count} requests)")
                return True, "rate_limit_exceeded"
            
            # Add current request
            self.requests[client_ip].append(current_time)
            
            # Log high usage (warning at 80% of limit)
            if request_count >= self.requests_per_minute * 0.8:
                self.logger.info(f"High request rate for IP {client_ip}: {request_count}/{self.requests_per_minute}")
            
            return False, None
    
    def increment_counter(self, client_ip: str) -> None:
        """
        Increment request counter for IP (alternative method)
        
        Args:
            client_ip: Client IP address
        """
        current_time = time.time()
        
        with self.lock:
            self.requests[client_ip].append(current_time)
            
            # Auto-clean old requests
            self._clean_old_requests(client_ip, current_time)
    
    def get_request_count(self, client_ip: str, window_seconds: int = 60) -> int:
        """
        Get current request count for IP in specified time window
        
        Args:
            client_ip: IP to check
            window_seconds: Time window in seconds
            
        Returns:
            Number of requests in the time window
        """
        current_time = time.time()
        
        with self.lock:
            if client_ip not in self.requests:
                return 0
            
            count = len([
                req_time for req_time in self.requests[client_ip]
                if current_time - req_time < window_seconds
            ])
            return count
    
    def is_ip_blocked(self, client_ip: str) -> bool:
        """
        Check if IP is currently blocked
        
        Args:
            client_ip: IP to check
            
        Returns:
            True if blocked
        """
        with self.lock:
            return self._is_ip_blocked(client_ip, time.time())
    
    def get_block_remaining_time(self, client_ip: str) -> float:
        """
        Get remaining block time for IP
        
        Args:
            client_ip: IP to check
            
        Returns:
            Remaining block time in seconds, 0 if not blocked
        """
        with self.lock:
            return self._get_block_remaining_time(client_ip, time.time())
    
    def clear_ip(self, client_ip: str) -> bool:
        """
        Clear all rate limit data for an IP (unblock and clear history)
        
        Args:
            client_ip: IP to clear
            
        Returns:
            True if IP was found and cleared
        """
        with self.lock:
            ip_found = False
            
            if client_ip in self.requests:
                del self.requests[client_ip]
                ip_found = True
            
            if client_ip in self.blocked_ips:
                del self.blocked_ips[client_ip]
                ip_found = True
            
            if ip_found:
                self.logger.info(f"Cleared rate limit data for IP {client_ip}")
            
            return ip_found
    
    def _is_ip_blocked(self, client_ip: str, current_time: float) -> bool:
        """Check if IP is blocked (internal, assumes lock acquired)"""
        if client_ip not in self.blocked_ips:
            return False
        
        block_time = self.blocked_ips[client_ip]
        if current_time - block_time < self.block_duration:
            return True
        else:
            # Block expired
            del self.blocked_ips[client_ip]
            return False
    
    def _get_block_remaining_time(self, client_ip: str, current_time: float) -> float:
        """Get remaining block time (internal, assumes lock acquired)"""
        if client_ip not in self.blocked_ips:
            return 0.0
        
        block_time = self.blocked_ips[client_ip]
        elapsed = current_time - block_time
        remaining = self.block_duration - elapsed
        
        return max(0.0, remaining)
    
    def _block_ip(self, client_ip: str, current_time: float) -> None:
        """Block an IP (internal, assumes lock acquired)"""
        self.blocked_ips[client_ip] = current_time
    
    def _clean_old_requests(self, client_ip: str, current_time: float) -> None:
        """Clean old requests for an IP (internal, assumes lock acquired)"""
        if client_ip in self.requests:
            # Keep only requests from last 2 minutes (for stats)
            self.requests[client_ip] = [
                req_time for req_time in self.requests[client_ip]
                if current_time - req_time < 120
            ]
            
            # Remove IP if no recent requests
            if not self.requests[client_ip]:
                del self.requests[client_ip]
    
    def _cleanup_old_data(self, current_time: float) -> None:
        """Clean up old request data and expired blocks (internal)"""
        cleaned_count = 0
        
        # Clean old requests (older than 2 minutes)
        for ip in list(self.requests.keys()):
            self.requests[ip] = [
                req_time for req_time in self.requests[ip]
                if current_time - req_time < 120
            ]
            if not self.requests[ip]:
                del self.requests[ip]
                cleaned_count += 1
        
        # Clean expired blocks
        expired_blocks = []
        for ip, block_time in self.blocked_ips.items():
            if current_time - block_time >= self.block_duration:
                expired_blocks.append(ip)
        
        for ip in expired_blocks:
            del self.blocked_ips[ip]
            cleaned_count += 1
        
        if cleaned_count > 0:
            self.logger.debug(f"Cleaned up {cleaned_count} expired rate limit entries")
    
    def get_stats(self) -> Dict[str, any]:
        """Get rate limiter statistics"""
        current_time = time.time()
        
        with self.lock:
            active_requests = sum(len(times) for times in self.requests.values())
            active_blocks = len([
                ip for ip in self.blocked_ips 
                if self._is_ip_blocked(ip, current_time)
            ])
            
            # Calculate requests per minute for each IP
            ip_rates = {}
            for ip, times in self.requests.items():
                recent_requests = [t for t in times if current_time - t < 60]
                ip_rates[ip] = len(recent_requests)
            
            return {
                "active_requests_tracked": active_requests,
                "active_blocks": active_blocks,
                "unique_ips_tracked": len(self.requests),
                "limit_per_minute": self.requests_per_minute,
                "block_duration_seconds": self.block_duration,
                "ip_request_rates": ip_rates
            }
    
    def get_detailed_stats(self) -> Dict[str, any]:
        """Get detailed statistics for dashboard"""
        stats = self.get_stats()
        
        # Add top offenders
        current_time = time.time()
        with self.lock:
            top_offenders = []
            for ip, times in self.requests.items():
                recent_count = len([t for t in times if current_time - t < 60])
                if recent_count > self.requests_per_minute * 0.5:  # Over 50% of limit
                    top_offenders.append({
                        "ip": ip,
                        "requests_per_minute": recent_count,
                        "is_blocked": self._is_ip_blocked(ip, current_time),
                        "block_remaining": self._get_block_remaining_time(ip, current_time)
                    })
            
            # Sort by request rate (descending)
            top_offenders.sort(key=lambda x: x["requests_per_minute"], reverse=True)
            stats["top_offenders"] = top_offenders[:10]  # Top 10
        
        return stats


# Factory function
def create_rate_limiter(requests_per_minute: int = 100, block_duration: int = 300) -> RateLimiter:
    """Create and return a RateLimiter instance"""
    return RateLimiter(requests_per_minute, block_duration)


# Self-test
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    print("🧪 Testing Rate Limiter\n")
    
    # Test with low limits for testing
    limiter = create_rate_limiter(requests_per_minute=5, block_duration=10)
    
    test_ip = "192.168.1.100"
    
    print("[TEST 1] Normal request pattern")
    for i in range(3):
        blocked, reason = limiter.rate_limit_check(test_ip)
        print(f"  Request {i+1}: blocked={blocked}, reason={reason}")
    
    print("\n[TEST 2] Exceeding limit")
    for i in range(3, 7):  # This should trigger blocking
        blocked, reason = limiter.rate_limit_check(test_ip)
        print(f"  Request {i+1}: blocked={blocked}, reason={reason}")
    
    print("\n[TEST 3] Blocked status")
    print(f"  Is IP blocked: {limiter.is_ip_blocked(test_ip)}")
    print(f"  Block remaining: {limiter.get_block_remaining_time(test_ip):.1f}s")
    
    print("\n[TEST 4] Request count")
    count = limiter.get_request_count(test_ip)
    print(f"  Requests in last minute: {count}")
    
    print("\n[TEST 5] Statistics")
    stats = limiter.get_stats()
    print(f"  Active blocks: {stats['active_blocks']}")
    print(f"  Unique IPs tracked: {stats['unique_ips_tracked']}")
    print(f"  IP request rates: {stats['ip_request_rates']}")
    
    print("\n[TEST 6] Clear IP")
    cleared = limiter.clear_ip(test_ip)
    print(f"  IP cleared: {cleared}")
    print(f"  Is IP blocked after clear: {limiter.is_ip_blocked(test_ip)}")
    
    print("\n✅ Rate limiter test completed!")