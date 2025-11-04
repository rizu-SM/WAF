# src/security/ip_manager.py
import time
import json
import logging
from pathlib import Path
from threading import Lock
from typing import Dict, Optional, List, Any, Tuple

DEFAULT_STORAGE = "config/blocked_ips.json"


class IPManager:
    """
    Enhanced IP Manager with persistence, violation tracking, and auto-blocking
    - blocked_ips: Dict[ip, {unblock_at: float, reason: str, metadata: {...}}]
    - whitelist: set of IPs (permanent bypass)
    - violation_tracking: Dict[ip, {count: int, last_seen: float, violations: list}]
    Thread-safe with disk persistence and auto-blocking capabilities.
    """

    def __init__(self, storage_path: str = DEFAULT_STORAGE, persist: bool = True,
                 auto_block: bool = True, block_threshold: int = 10, 
                 default_block_duration: int = 3600):
        self.logger = logging.getLogger(__name__)
        self.lock = Lock()
        
        # Core storage
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}
        self.whitelist: Dict[str, Dict[str, Any]] = {}
        self.violation_tracking: Dict[str, Dict[str, Any]] = {}
        
        # Configuration
        self.storage_file = Path(storage_path)
        self.persist = persist
        self.auto_block = auto_block
        self.block_threshold = block_threshold
        self.default_block_duration = default_block_duration

        # Ensure parent dir exists for persistence
        try:
            if self.storage_file.parent:
                self.storage_file.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            # ignore permission errors here; persistence will fail gracefully
            pass

        # Load persisted state if requested
        if self.persist:
            self._load_from_disk()

        self.logger.info(
            "IPManager initialized (persist=%s, auto_block=%s, threshold=%d)", 
            self.persist, self.auto_block, self.block_threshold
        )

    # -------------------------
    # Core Blocking API (Your Clean Design)
    # -------------------------
    def block_ip(self, ip: str, duration_seconds: Optional[int] = None, 
                 reason: str = "manual_block", metadata: Optional[dict] = None) -> bool:
        """
        Block an IP. If duration_seconds is None -> permanent block (unblock_at = None).
        Returns True if blocked, False if whitelisted.
        """
        # Check if IP is whitelisted
        if self.is_whitelisted(ip):
            self.logger.info("Cannot block whitelisted IP: %s", ip)
            return False
            
        unblock_at = None if duration_seconds is None else time.time() + int(duration_seconds)
        with self.lock:
            self.blocked_ips[ip] = {
                "unblock_at": unblock_at,
                "reason": reason,
                "metadata": metadata or {},
                "blocked_at": time.time()
            }
            self.logger.warning("Blocked IP %s (duration=%s, reason=%s)", ip, duration_seconds, reason)
            if self.persist:
                self._save_to_disk()
            return True

    def temp_block_ip(self, ip: str, duration_seconds: int = 300, 
                     reason: str = "auto_block", metadata: Optional[dict] = None) -> bool:
        """Convenience to block temporarily (default 300s)."""
        return self.block_ip(ip, duration_seconds=duration_seconds, reason=reason, metadata=metadata)

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP. Returns True if removed, False if not found."""
        with self.lock:
            removed = False
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                removed = True
                self.logger.info("Unblocked IP %s", ip)
            if self.persist and removed:
                self._save_to_disk()
            return removed

    # -------------------------
    # Whitelist API (Your Clean Design)
    # -------------------------
    def whitelist_ip(self, ip: str, note: str = "") -> None:
        """Add IP to whitelist (permanent bypass)."""
        with self.lock:
            self.whitelist[ip] = {"note": note, "added_at": time.time()}
            # Auto-remove from blocks and violation tracking
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
            if ip in self.violation_tracking:
                del self.violation_tracking[ip]
            self.logger.info("Whitelisted IP %s (%s)", ip, note)
            if self.persist:
                self._save_to_disk()

    def remove_whitelist(self, ip: str) -> bool:
        """Remove IP from whitelist. Returns True if removed."""
        with self.lock:
            if ip in self.whitelist:
                del self.whitelist[ip]
                if self.persist:
                    self._save_to_disk()
                self.logger.info("Removed IP %s from whitelist", ip)
                return True
            return False

    # -------------------------
    # Enhanced Violation Tracking (Best of My Version)
    # -------------------------
    def record_violation(self, ip: str, violation_type: str, 
                        severity: str = "medium", details: Dict = None) -> bool:
        """
        Record a security violation for an IP.
        Returns True if auto-block was triggered.
        """
        # Skip if whitelisted
        if self.is_whitelisted(ip):
            return False

        current_time = time.time()
        with self.lock:
            # Initialize tracking if first violation
            if ip not in self.violation_tracking:
                self.violation_tracking[ip] = {
                    "count": 0,
                    "violations": [],
                    "first_seen": current_time,
                    "last_seen": current_time
                }

            ip_info = self.violation_tracking[ip]
            ip_info["count"] += 1
            ip_info["last_seen"] = current_time

            # Record violation details (keep last 50)
            violation_record = {
                "timestamp": current_time,
                "type": violation_type,
                "severity": severity,
                "details": details or {}
            }
            ip_info["violations"].append(violation_record)
            if len(ip_info["violations"]) > 50:
                ip_info["violations"] = ip_info["violations"][-50:]

            self.logger.info(
                "Violation recorded for %s: %s (severity: %s, total: %d)", 
                ip, violation_type, severity, ip_info['count']
            )

            # Auto-block if threshold reached
            auto_blocked = False
            if (self.auto_block and 
                ip_info["count"] >= self.block_threshold and
                not self.is_blocked(ip)):
                
                block_reason = f"Auto-block after {ip_info['count']} violations"
                self.temp_block_ip(ip, self.default_block_duration, block_reason, 
                                 {"violation_type": violation_type})
                auto_blocked = True

            if self.persist:
                self._save_to_disk()

            return auto_blocked

    def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Get reputation information for an IP (simplified from my version)"""
        current_time = time.time()
        reputation = {
            "ip": ip,
            "is_whitelisted": self.is_whitelisted(ip),
            "is_blocked": self.is_blocked(ip),
            "violation_count": 0,
            "reputation_score": 100,  # Start with perfect score
            "block_remaining": self.get_block_remaining_time(ip)
        }

        with self.lock:
            if ip in self.violation_tracking:
                ip_info = self.violation_tracking[ip]
                reputation["violation_count"] = ip_info["count"]
                reputation["first_seen"] = ip_info["first_seen"]
                reputation["last_seen"] = ip_info["last_seen"]
                
                # Simple reputation score (100 - violations * 10, min 0)
                reputation["reputation_score"] = max(0, 100 - (ip_info["count"] * 10))

            if ip in self.blocked_ips:
                block_info = self.blocked_ips[ip]
                reputation["block_reason"] = block_info["reason"]
                reputation["blocked_at"] = block_info["blocked_at"]

        return reputation

    # -------------------------
    # Query API (Your Clean Design)
    # -------------------------
    def is_whitelisted(self, ip: str) -> bool:
        """Return True if IP is whitelisted."""
        with self.lock:
            return ip in self.whitelist

    def is_blocked(self, ip: str) -> bool:
        """
        Return True if IP is currently blocked.
        Also auto-cleans expired blocks.
        """
        with self.lock:
            info = self.blocked_ips.get(ip)
            if not info:
                return False
            unblock_at = info.get("unblock_at")
            if unblock_at is None:
                # Permanent block
                return True
            if time.time() < unblock_at:
                return True
            # expired -> remove it
            del self.blocked_ips[ip]
            if self.persist:
                self._save_to_disk()
            return False

    def get_block_remaining_time(self, ip: str) -> float:
        """Return remaining seconds until unblock. 0 if not blocked or permanent block (inf -> returns -1)."""
        with self.lock:
            info = self.blocked_ips.get(ip)
            if not info:
                return 0.0
            unblock_at = info.get("unblock_at")
            if unblock_at is None:
                return -1.0  # represent permanent block
            remaining = unblock_at - time.time()
            return max(0.0, remaining)

    # -------------------------
    # Enhanced Reporting (Best of Both)
    # -------------------------
    def get_blocked_ips(self) -> Dict[str, Dict[str, Any]]:
        """Return blocked IPs (removes expired entries first)."""
        with self.lock:
            self._cleanup_expired_locked()
            return dict(self.blocked_ips)

    def get_whitelist(self) -> Dict[str, Dict[str, Any]]:
        """Return whitelist."""
        with self.lock:
            return dict(self.whitelist)

    def get_suspicious_ips(self, min_violations: int = 1) -> List[Dict[str, Any]]:
        """Get list of suspicious IPs with violation counts."""
        with self.lock:
            suspicious_list = []
            for ip, info in self.violation_tracking.items():
                if info["count"] >= min_violations and not self.is_whitelisted(ip):
                    suspicious_list.append({
                        "ip": ip,
                        "violation_count": info["count"],
                        "last_seen": info["last_seen"],
                        "recent_violation_types": list(set(
                            v["type"] for v in info["violations"][-5:]  # Last 5 violations
                        ))
                    })
            
            # Sort by violation count (descending)
            suspicious_list.sort(key=lambda x: x["violation_count"], reverse=True)
            return suspicious_list

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics."""
        with self.lock:
            self._cleanup_expired_locked()
            
            # Calculate active blocks (non-expired)
            active_blocks = len([
                ip for ip in self.blocked_ips 
                if self.is_blocked(ip)
            ])
            
            return {
                "blocked_ips_total": len(self.blocked_ips),
                "blocked_ips_active": active_blocks,
                "whitelisted_ips": len(self.whitelist),
                "suspicious_ips": len(self.violation_tracking),
                "auto_block_enabled": self.auto_block,
                "block_threshold": self.block_threshold,
                "default_block_duration": self.default_block_duration
            }

    # -------------------------
    # Internal - persistence & cleanup
    # -------------------------
    def _cleanup_expired_locked(self) -> None:
        """Remove expired blocks and old violations. Assumes lock is held."""
        current_time = time.time()
        
        # Clean expired blocks
        expired_blocks = []
        for ip, info in list(self.blocked_ips.items()):
            unblock_at = info.get("unblock_at")
            if unblock_at is not None and current_time >= unblock_at:
                expired_blocks.append(ip)
        for ip in expired_blocks:
            del self.blocked_ips[ip]
        
        # Clean old violations (older than 30 days)
        old_violations = []
        for ip, info in list(self.violation_tracking.items()):
            # Remove IP if no recent violations (30 days) and not blocked
            if (current_time - info["last_seen"] > 2592000 and  # 30 days
                not self.is_blocked(ip)):
                old_violations.append(ip)
        for ip in old_violations:
            del self.violation_tracking[ip]
        
        if (expired_blocks or old_violations) and self.persist:
            self._save_to_disk()
            if expired_blocks or old_violations:
                self.logger.debug("Cleanup: %d expired blocks, %d old violations", 
                                len(expired_blocks), len(old_violations))

    def cleanup_expired(self) -> None:
        """Public method to trigger cleanup."""
        with self.lock:
            self._cleanup_expired_locked()

    def _load_from_disk(self) -> None:
        """Load persisted state from disk."""
        try:
            if not self.storage_file.exists():
                return
            data = json.loads(self.storage_file.read_text(encoding="utf-8"))
            
            # Load all components
            self.blocked_ips = data.get("blocked_ips", {})
            self.whitelist = data.get("whitelist", {})
            self.violation_tracking = data.get("violation_tracking", {})
            
            self.logger.info("Loaded IP manager state from %s", self.storage_file)
        except Exception as e:
            self.logger.error("Failed to load IP manager state: %s", e)

    def _save_to_disk(self) -> None:
        """Persist current state to disk (best-effort)."""
        try:
            payload = {
                "blocked_ips": self.blocked_ips,
                "whitelist": self.whitelist,
                "violation_tracking": self.violation_tracking,
                "saved_at": time.time()
            }
            self.storage_file.write_text(json.dumps(payload, default=str, indent=2), encoding="utf-8")
        except Exception as e:
            self.logger.error("Failed to save IP manager state: %s", e)

    # -------------------------
    # Utility
    # -------------------------
    def clear_all(self) -> None:
        """Remove all data (useful for tests)."""
        with self.lock:
            self.blocked_ips.clear()
            self.whitelist.clear()
            self.violation_tracking.clear()
            if self.persist:
                self._save_to_disk()
            self.logger.info("Cleared all IPManager state")


# -------------------------
# Singleton factory
# -------------------------
_ip_manager_instance: Optional[IPManager] = None

def get_ip_manager(storage_path: str = DEFAULT_STORAGE, persist: bool = True,
                  auto_block: bool = True, block_threshold: int = 10,
                  default_block_duration: int = 3600) -> IPManager:
    """Return a singleton IPManager instance."""
    global _ip_manager_instance
    if _ip_manager_instance is None:
        _ip_manager_instance = IPManager(
            storage_path, persist, auto_block, block_threshold, default_block_duration
        )
    return _ip_manager_instance


# Self-test
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    print("🧪 Testing Enhanced IP Manager\n")
    
    # Test with persistence disabled for testing
    mgr = IPManager(persist=False, auto_block=True, block_threshold=3)
    test_ip = "192.168.1.100"
    
    print("[TEST 1] Violation Tracking with Auto-block")
    for i in range(4):
        auto_blocked = mgr.record_violation(test_ip, "sql_injection", "high", {"pattern": "OR 1=1"})
        print(f"  Violation {i+1}: count={mgr.get_ip_reputation(test_ip)['violation_count']}, auto_blocked={auto_blocked}")
    
    print(f"\n  Is IP blocked: {mgr.is_blocked(test_ip)}")
    print(f"  Block remaining: {mgr.get_block_remaining_time(test_ip):.1f}s")
    
    print("\n[TEST 2] Whitelist Protection")
    mgr.whitelist_ip("192.168.1.200", "internal server")
    blocked = mgr.block_ip("192.168.1.200", 300, "test")
    print(f"  Can block whitelisted IP: {blocked}")
    print(f"  Is whitelisted IP blocked: {mgr.is_blocked('192.168.1.200')}")
    
    print("\n[TEST 3] IP Reputation")
    reputation = mgr.get_ip_reputation(test_ip)
    print(f"  Reputation score: {reputation['reputation_score']}")
    print(f"  Violation count: {reputation['violation_count']}")
    print(f"  Is blocked: {reputation['is_blocked']}")
    
    print("\n[TEST 4] Statistics")
    stats = mgr.get_stats()
    print(f"  Active blocks: {stats['blocked_ips_active']}")
    print(f"  Suspicious IPs: {stats['suspicious_ips']}")
    print(f"  Whitelisted: {stats['whitelisted_ips']}")
    
    print("\n[TEST 5] Suspicious IPs List")
    suspicious = mgr.get_suspicious_ips(min_violations=1)
    print(f"  Found {len(suspicious)} suspicious IPs")
    for ip_info in suspicious:
        print(f"    {ip_info['ip']}: {ip_info['violation_count']} violations")
    
    print("\n✅ Enhanced IP Manager test completed!")