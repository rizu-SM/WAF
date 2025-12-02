# src/core/waf.py
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import parse_qs

from .config_loader import get_config_loader
from src.detection.sql_injection import detect_sql_injection
from src.detection.xss import detect_xss
from src.detection.path_traversal import detect_path_traversal
from src.utils.logger import get_waf_logger, setup_logging
from src.security.ip_manager import get_ip_manager
from src.security.rate_limiter import create_rate_limiter

@dataclass
class WAFRequest:
    """Represents an HTTP request for WAF processing"""
    method: str
    path: str
    headers: Dict[str, str] 
    body: str = ""
    client_ip: str = ""
    query_params: Dict[str, str] = field(default_factory=dict)

@dataclass  
class WAFResponse:
    """Represents WAF decision and response"""
    allowed: bool
    action: str  # allow, block, challenge
    reason: str = ""
    confidence: str = ""
    status_code: int = 200
    details: Dict[str, Any] = field(default_factory=dict)

class PyWAF:
    """
    Main Web Application Firewall class.
    Orchestrates detection engines and makes security decisions.
    """
    
    def __init__(self):
        # Use WAFLogger instead of basic logger
        self.logger = logging.getLogger(__name__)
        self.waf_logger = get_waf_logger()  # ← ADD THIS
        
        self.config_loader = get_config_loader()
        
        # Load initial configuration
        self.config = self.config_loader.get_config()
        self.rules = self.config_loader.get_rules()
        self.whitelist_ips = self.config_loader.get_whitelist_ips()
        self.whitelist_paths = self.config_loader.get_whitelist_paths()
        
        # Enhanced statistics
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "allowed_requests": 0,
            "challenges_issued": 0,
            "by_attack_type": {}
        }
        
        # Initialize security components (IP Manager & Rate Limiter)
        security_config = self.config.get('security', {})
        rate_limit_config = security_config.get('rate_limiting', {})
        
        self.ip_manager = get_ip_manager(
            persist=True,
            auto_block=True,
            block_threshold=security_config.get('bruteforce_protection', {}).get('max_attempts', 10),
            default_block_duration=rate_limit_config.get('block_duration', 300)
        )
        
        self.rate_limiter = create_rate_limiter(
            requests_per_minute=rate_limit_config.get('requests_per_minute', 100),
            block_duration=rate_limit_config.get('block_duration', 300)
        )
        
        self.rate_limiting_enabled = rate_limit_config.get('enabled', True)
        
        self.logger.info("PyWAF initialized successfully")
        self.logger.info(f"Mode: {self.config['waf']['mode']}")
        self.logger.info(f"Backend: {self.config['waf']['backend_url']}")
        self.logger.info(f"Rate limiting: {'enabled' if self.rate_limiting_enabled else 'disabled'}")
        self.logger.info(f"IP auto-block threshold: {self.ip_manager.block_threshold} violations")
        
        # Setup file logging based on config
        log_config = self.config.get('logging', {})
        log_file = log_config.get('file', 'logs/waf.log')
        use_json = log_config.get('format', 'text') == 'json'
        
        self.waf_logger.setup_file_logging(
            log_file=log_file,
            max_size_mb=log_config.get('max_size_mb', 100),
            backup_count=log_config.get('backup_count', 5),
            use_json=use_json
        )
    
    def process_request(self, request: WAFRequest) -> WAFResponse:
        """
        Main entry point - process an HTTP request through the WAF
        
        Args:
            request: The HTTP request to analyze
            
        Returns:
            WAFResponse with decision and details
        """
        self.stats["total_requests"] += 1
        self.logger.debug(f"Processing request: {request.method} {request.path}")
        
        # Step 1: Check if WAF is enabled
        if not self.config['waf']['enabled']:
            self.logger.debug("WAF disabled - allowing request")
            self.stats["allowed_requests"] += 1
            return WAFResponse(allowed=True, action="allow", reason="waf_disabled")
        
        # Step 1.5: Whitelist checks FIRST (bypass all security for whitelisted IPs)
        whitelist_check = self._check_whitelists(request)
        if whitelist_check:
            self.waf_logger.log_whitelist_bypass(
                client_ip=request.client_ip,
                reason=whitelist_check,
                path=request.path
            )
            self.stats["allowed_requests"] += 1
            return WAFResponse(allowed=True, action="allow", reason=whitelist_check)
        
        # Step 2: Check if IP is blocked by IPManager
        if self.ip_manager.is_blocked(request.client_ip):
            remaining = self.ip_manager.get_block_remaining_time(request.client_ip)
            self.logger.warning(f"Blocked IP {request.client_ip} attempted access ({remaining:.0f}s remaining)")
            self.stats["blocked_requests"] += 1
            return WAFResponse(
                allowed=False,
                action="block",
                reason="ip_blocked",
                status_code=403,
                details={
                    "block_remaining_seconds": remaining,
                    "reputation": self.ip_manager.get_ip_reputation(request.client_ip)
                }
            )
        
        # Step 3: Rate limiting check
        if self.rate_limiting_enabled:
            rate_limited, rate_reason = self.rate_limiter.rate_limit_check(request.client_ip)
            if rate_limited:
                self.logger.warning(f"Rate limit exceeded for IP {request.client_ip}: {rate_reason}")
                self.stats["blocked_requests"] += 1
                # Record as violation for potential auto-block
                self.ip_manager.record_violation(
                    request.client_ip,
                    "rate_limit_exceeded",
                    severity="medium",
                    details={"reason": rate_reason, "path": request.path}
                )
                return WAFResponse(
                    allowed=False,
                    action="block",
                    reason=f"rate_limited:{rate_reason}",
                    status_code=429,
                    details={"rate_limit_reason": rate_reason}
                )
        
        # Step 4: Build request dictionary for detectors
        request_dict = self._build_request_dict(request)
        
        # Step 4: Run security detectors
        detection_results = self._run_detectors(request_dict)
        
        # Step 5: Make final decision
        final_decision = self._make_decision(detection_results, request)
        
        # Step 6: Log decision (using WAFLogger)
        self._log_decision_structured(request, final_decision, detection_results)
        
        # Step 7: Update statistics
        self._update_stats(final_decision, detection_results)
        
        return final_decision
    
    def _check_whitelists(self, request: WAFRequest) -> Optional[str]:
        """Check if request matches any whitelist rules"""
        
        # IP whitelist (config-based)
        if request.client_ip in self.whitelist_ips:
            return f"ip_whitelisted:{request.client_ip}"
        
        # IP whitelist (IPManager-based - dynamic whitelist)
        if self.ip_manager.is_whitelisted(request.client_ip):
            return f"ip_manager_whitelisted:{request.client_ip}"
        
        # Path whitelist
        for whitelisted_path in self.whitelist_paths:
            if request.path.startswith(whitelisted_path):
                return f"path_whitelisted:{request.path}"
        
        return None
    
    def _build_request_dict(self, request: WAFRequest) -> Dict[str, Any]:
        """Build standardized request dictionary for detectors"""
        # Parse body if it's form data
        body_params = {}
        if request.body and request.method in ['POST', 'PUT', 'PATCH']:
            try:
                body_params = {
                    k: v[0] if len(v) == 1 else v 
                    for k, v in parse_qs(request.body).items()
                }
            except:
                self.logger.debug("Failed to parse body as form data")
        
        return {
            "path": request.path,
            "args": request.query_params,
            "body": request.body,
            "body_params": body_params,
            "headers": request.headers,
            "method": request.method,
            "client_ip": request.client_ip
        }
    
    def _run_detectors(self, request_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Run all enabled detection engines against the request"""
        results = {
            "detections": [],
            "block_recommended": False,
            "high_confidence_attack": False
        }
        
        # Check 1: Payload length limit
        max_length = self.config['waf'].get('max_payload_length', 2000)
        total_payload = len(request_dict.get('body', ''))
        
        if total_payload > max_length:
            self.logger.warning(f"Payload too large: {total_payload} > {max_length}")
            results["detections"].append({
                "type": "payload_too_large",
                "details": {
                    "reason": "payload_size_exceeded",
                    "confidence": "high",
                    "size": total_payload,
                    "limit": max_length
                },
                "confidence": "high"
            })
            results["high_confidence_attack"] = True
            results["block_recommended"] = True
            return results
        
        # Check 2: SQL Injection Detection
        if self.config_loader.is_detection_enabled("sql_injection"):
            sql_patterns = self.rules.get('sql_injection', [])
            sql_attack, sql_details = detect_sql_injection(request_dict, sql_patterns)
            
            if sql_attack:
                self.logger.debug(f"SQL injection detected: {sql_details}")
                results["detections"].append({
                    "type": "sql_injection",
                    "details": sql_details,
                    "confidence": sql_details.get("confidence", "medium")
                })
                if sql_details.get("confidence") == "high":
                    results["high_confidence_attack"] = True
                results["block_recommended"] = True
        
        # Check 3: XSS Detection
        if self.config_loader.is_detection_enabled("xss"):
            xss_patterns = self.rules.get('xss', [])
            xss_attack, xss_details = detect_xss(request_dict, xss_patterns)
            
            if xss_attack:
                self.logger.debug(f"XSS attack detected: {xss_details}")
                results["detections"].append({
                    "type": "xss",
                    "details": xss_details,
                    "confidence": xss_details.get("confidence", "medium")
                })
                if xss_details.get("confidence") == "high":
                    results["high_confidence_attack"] = True
                results["block_recommended"] = True
        
        # Check 4: Path Traversal Detection
        if self.config_loader.is_detection_enabled("path_traversal"):
            path_patterns = self.rules.get('path_traversal', [])
            path_attack, path_details = detect_path_traversal(request_dict, path_patterns)
            
            if path_attack:
                self.logger.debug(f"Path traversal detected: {path_details}")
                results["detections"].append({
                    "type": "path_traversal",
                    "details": path_details,
                    "confidence": path_details.get("confidence", "medium")
                })
                if path_details.get("confidence") == "high":
                    results["high_confidence_attack"] = True
                results["block_recommended"] = True
        
        return results
    
    def _make_decision(self, detection_results: Dict[str, Any], request: WAFRequest) -> WAFResponse:
        """Make final decision based on detection results and WAF mode"""
        waf_mode = self.config['waf']['mode']
        
        # No detections - allow request
        if not detection_results["detections"]:
            return WAFResponse(
                allowed=True, 
                action="allow", 
                reason="no_detections"
            )
        
        # Get first detection (primary threat)
        primary_detection = detection_results["detections"][0]
        attack_type = primary_detection["type"]
        confidence = primary_detection.get("confidence", "medium")
        
        # Record violation in IPManager for tracking and potential auto-block
        severity_map = {"high": "high", "medium": "medium", "low": "low"}
        self.ip_manager.record_violation(
            request.client_ip,
            violation_type=attack_type,
            severity=severity_map.get(confidence, "medium"),
            details={
                "path": request.path,
                "method": request.method,
                "detection_details": primary_detection.get("details", {})
            }
        )
        
        # High confidence attacks - always block regardless of mode
        if detection_results["high_confidence_attack"]:
            return WAFResponse(
                allowed=False,
                action="block",
                reason=f"high_confidence_{attack_type}",
                confidence="high",
                status_code=403,
                details={
                    "attack_type": attack_type,
                    "detection_details": primary_detection.get("details", {})
                }
            )
        
        # Handle based on WAF mode
        if waf_mode == "block":
            return WAFResponse(
                allowed=False,
                action="block", 
                reason=f"blocked_{attack_type}",
                confidence=confidence,
                status_code=403,
                details={
                    "attack_type": attack_type,
                    "detection_details": primary_detection.get("details", {})
                }
            )
        
        elif waf_mode == "log":
            return WAFResponse(
                allowed=True,
                action="allow",
                reason=f"logged_{attack_type}",
                confidence=confidence,
                details={
                    "attack_type": attack_type,
                    "logged": True,
                    "detection_details": primary_detection.get("details", {})
                }
            )
        
        elif waf_mode == "challenge":
            return WAFResponse(
                allowed=False,
                action="challenge",
                reason="challenge_required",
                status_code=429,
                details={
                    "challenge_type": "captcha",
                    "attack_type": attack_type
                }
            )
        
        # Fallback
        return WAFResponse(allowed=True, action="allow", reason="fallback")
    
    def _log_decision_structured(self, request: WAFRequest, decision: WAFResponse, 
                                 detection_results: Dict[str, Any]) -> None:
        """
        ✅ NEW: Log decision using structured WAFLogger
        This replaces the old _log_decision method
        """
        detection_count = len(detection_results.get("detections", []))
        
        if not decision.allowed:
            # Request was blocked or challenged
            if decision.action == "block":
                attack_type = decision.details.get("attack_type", "unknown")
                self.waf_logger.log_request_blocked(
                    reason=decision.reason,
                    attack_type=attack_type,
                    client_ip=request.client_ip,
                    details={
                        "method": request.method,
                        "path": request.path,
                        "confidence": decision.confidence,
                        "detection_details": decision.details.get("detection_details", {})
                    }
                )
            elif decision.action == "challenge":
                self.waf_logger.log_challenge_issued(
                    client_ip=request.client_ip,
                    challenge_type=decision.details.get("challenge_type", "captcha"),
                    reason=decision.reason
                )
        else:
            # Request was allowed
            self.waf_logger.log_request_allowed(
                client_ip=request.client_ip,
                path=request.path,
                detection_count=detection_count
            )
    
    def _update_stats(self, decision: WAFResponse, detections: Dict[str, Any]):
        """Update WAF statistics"""
        # Update counters
        if decision.allowed:
            self.stats["allowed_requests"] += 1
        else:
            if decision.action == "block":
                self.stats["blocked_requests"] += 1
            elif decision.action == "challenge":
                self.stats["challenges_issued"] += 1
        
        # Track by attack type
        for detection in detections.get("detections", []):
            attack_type = detection.get("type", "unknown")
            
            if attack_type not in self.stats["by_attack_type"]:
                self.stats["by_attack_type"][attack_type] = {
                    "detected": 0,
                    "blocked": 0,
                    "logged": 0
                }
            
            self.stats["by_attack_type"][attack_type]["detected"] += 1
            
            if decision.action == "block":
                self.stats["by_attack_type"][attack_type]["blocked"] += 1
            elif decision.action == "allow" and "logged" in decision.reason:
                self.stats["by_attack_type"][attack_type]["logged"] += 1
    
    def reload_configuration(self) -> bool:
        """Reload all configuration and rules"""
        try:
            if self.config_loader.reload_all():
                self.config = self.config_loader.get_config()
                self.rules = self.config_loader.get_rules()
                self.whitelist_ips = self.config_loader.get_whitelist_ips()
                self.whitelist_paths = self.config_loader.get_whitelist_paths()
                
                # ✅ ADD: Log configuration reload
                self.waf_logger.log_config_change(
                    component="waf",
                    action="reload",
                    details={"mode": self.config['waf']['mode']}
                )
                
                self.logger.info("Configuration reloaded successfully")
                return True
        except Exception as e:
            self.logger.error(f"Failed to reload configuration: {e}")
        return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current WAF statistics"""
        stats = self.stats.copy()
        
        # Add calculated metrics
        if stats["total_requests"] > 0:
            stats["block_rate"] = round(
                (stats["blocked_requests"] / stats["total_requests"]) * 100, 2
            )
        else:
            stats["block_rate"] = 0.0
        
        # Include logger statistics
        stats["logger_stats"] = self.waf_logger.get_stats()
        
        # Include security module statistics
        stats["ip_manager_stats"] = self.ip_manager.get_stats()
        stats["rate_limiter_stats"] = self.rate_limiter.get_stats()
        stats["suspicious_ips"] = self.ip_manager.get_suspicious_ips(min_violations=3)
        
        return stats
    
    def get_recent_events(self, limit: int = 100, event_type: str = None) -> list:
        """
        ✅ NEW: Get recent security events (for dashboard)
        
        Args:
            limit: Maximum number of events to return
            event_type: Filter by event type (optional)
            
        Returns:
            List of recent security events
        """
        return self.waf_logger.get_recent_events(limit, event_type)
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check of WAF components"""
        total_patterns = sum(len(patterns) for patterns in self.rules.values())
        ip_manager_stats = self.ip_manager.get_stats()
        rate_limiter_stats = self.rate_limiter.get_stats()
        
        return {
            "status": "healthy",
            "waf_enabled": self.config['waf']['enabled'],
            "mode": self.config['waf']['mode'],
            "backend": self.config['waf']['backend_url'],
            "detectors_enabled": {
                "sql_injection": self.config_loader.is_detection_enabled("sql_injection"),
                "xss": self.config_loader.is_detection_enabled("xss"),
                "path_traversal": self.config_loader.is_detection_enabled("path_traversal"),
            },
            "security_modules": {
                "rate_limiting_enabled": self.rate_limiting_enabled,
                "ip_auto_block_enabled": self.ip_manager.auto_block,
                "block_threshold": self.ip_manager.block_threshold,
                "blocked_ips_count": ip_manager_stats["blocked_ips_active"],
                "whitelisted_ips_count": ip_manager_stats["whitelisted_ips"],
                "suspicious_ips_count": ip_manager_stats["suspicious_ips"],
                "rate_limit_active_blocks": rate_limiter_stats["active_blocks"]
            },
            "total_patterns": total_patterns,
            "whitelisted_ips": len(self.whitelist_ips),
            "whitelisted_paths": len(self.whitelist_paths),
            "requests_processed": self.stats["total_requests"],
            "block_rate_percent": (
                round(
                    (self.stats["blocked_requests"] / self.stats["total_requests"]) * 100,
                    2
                )
                if self.stats["total_requests"] > 0 else 0.0
            ),
            "events_stored": len(self.waf_logger.security_events)
        }


# Singleton instance
_waf_instance = None

def get_waf() -> PyWAF:
    """Get or create singleton WAF instance"""
    global _waf_instance
    if _waf_instance is None:
        _waf_instance = PyWAF()
    return _waf_instance


# Self-test
if __name__ == "__main__":
    from src.utils.logger import setup_logging
    
    # ✅ CHANGE: Use WAFLogger setup instead of basic logging
    print("Testing PyWAF Core Engine with Enhanced Logging\n")
    print("="*60)
    
    # Setup logging (console + file with JSON)
    waf_logger = setup_logging(
        log_file="logs/waf.log",
        use_json=True,
        console_level=logging.INFO
    )
    
    waf = get_waf()
    
    # Test 1: Clean request
    print("\n[TEST 1] Clean Request")
    clean_request = WAFRequest(
        method="GET",
        path="/api/users",
        headers={"user-agent": "Mozilla/5.0"},
        client_ip="192.168.1.100",
        query_params={"page": "1"}
    )
    
    result = waf.process_request(clean_request)
    print(f"Result: {result.action} - {result.reason}")
    print(f"Allowed: {result.allowed}")
    
    # Test 2: SQL injection in query
    print("\n[TEST 2] SQL Injection in Query Parameter")
    sql_query_request = WAFRequest(
        method="GET", 
        path="/search",
        headers={"user-agent": "Mozilla/5.0"},
        client_ip="192.168.1.200",
        query_params={"q": "' OR 1=1--"}
    )
    
    result = waf.process_request(sql_query_request)
    print(f"Result: {result.action} - {result.reason}")
    print(f"Allowed: {result.allowed}")
    
    # Test 3: SQL injection in POST body
    print("\n[TEST 3] SQL Injection in POST Body")
    sql_body_request = WAFRequest(
        method="POST", 
        path="/login",
        headers={"user-agent": "Mozilla/5.0", "content-type": "application/x-www-form-urlencoded"},
        client_ip="192.168.1.201",
        body="username=admin' OR '1'='1'--&password=123"
    )
    
    result = waf.process_request(sql_body_request)
    print(f"Result: {result.action} - {result.reason}")
    print(f"Allowed: {result.allowed}")
    
    # Test 4: XSS attack
    print("\n[TEST 4] XSS Attack in Query Parameter")
    xss_request = WAFRequest(
        method="GET",
        path="/comment",
        headers={"user-agent": "Mozilla/5.0"},
        client_ip="192.168.1.202",
        query_params={"msg": "<script>alert('XSS')</script>"}
    )
    
    result = waf.process_request(xss_request)
    print(f"Result: {result.action} - {result.reason}")
    print(f"Allowed: {result.allowed}")
    
    # Test 5: Path Traversal attack
    print("\n[TEST 5] Path Traversal Attack")
    path_traversal_request = WAFRequest(
        method="GET",
        path="/files",
        headers={"user-agent": "Mozilla/5.0"},
        client_ip="192.168.1.203",
        query_params={"file": "../../etc/passwd"}
    )
    
    result = waf.process_request(path_traversal_request)
    print(f"Result: {result.action} - {result.reason}")
    print(f"Allowed: {result.allowed}")
    
    # Test 6: Whitelisted IP
    print("\n[TEST 6] Whitelisted IP (127.0.0.1)")
    whitelist_request = WAFRequest(
        method="GET",
        path="/admin",
        headers={"user-agent": "curl/7.0"},
        client_ip="127.0.0.1",
        query_params={"action": "' DROP TABLE users--"}
    )
    
    result = waf.process_request(whitelist_request)
    print(f"Result: {result.action} - {result.reason}")
    print(f"Allowed: {result.allowed}")
    
    # ✅ NEW: Show recent events
    print("\n" + "="*60)
    print("📋 Recent Security Events:")
    events = waf.get_recent_events(limit=5)
    for i, event in enumerate(events, 1):
        print(f"{i}. {event['event_type']} - {event['client_ip']} - {event.get('action', 'N/A')}")
    
    # Show statistics
    print("\n" + "="*60)
    print("📊 WAF Statistics:")
    stats = waf.get_statistics()
    print(f"Total Requests: {stats['total_requests']}")
    print(f"Blocked: {stats['blocked_requests']}")
    print(f"Allowed: {stats['allowed_requests']}")
    print(f"Block Rate: {stats['block_rate']}%")
    
    if stats['by_attack_type']:
        print("\nAttacks by Type:")
        for attack_type, counts in stats['by_attack_type'].items():
            print(f"  {attack_type}:")
            print(f"    Detected: {counts['detected']}")
            print(f"    Blocked: {counts['blocked']}")
            print(f"    Logged: {counts['logged']}")
    
    # Logger statistics
    logger_stats = stats.get('logger_stats', {})
    print(f"\nLogger: {logger_stats.get('total_events', 0)} events stored")
    
    # Health check
    print("\n" + "="*60)
    print("🏥 Health Check:")
    health = waf.health_check()
    for key, value in health.items():
        print(f"  {key}: {value}")
    
    print("\n✅ WAF core engine test completed!")
    print(f"📁 Logs saved to: logs/waf.log")