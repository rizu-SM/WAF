# src/core/waf.py
import logging #For recording events and errors
from typing import Dict, Any, Optional #
from dataclasses import dataclass, field
from urllib.parse import parse_qs

from .config_loader import get_config_loader
from src.detection.sql_injection import detect_sql_injection

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
        self.logger = logging.getLogger(__name__)
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
            "by_attack_type": {}  # Will store: {type: {detected, blocked, logged}}
        }
        
        self.logger.info("PyWAF initialized successfully")
        self.logger.info(f"Mode: {self.config['waf']['mode']}")
        self.logger.info(f"Backend: {self.config['waf']['backend_url']}")
    
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
        #If WAF is disabled: Let EVERYONE through without checks

        
        # Step 2: Whitelist checks
        whitelist_check = self._check_whitelists(request)
        if whitelist_check:
            self.logger.debug(f"Request whitelisted: {whitelist_check}")
            self.stats["allowed_requests"] += 1
            return WAFResponse(allowed=True, action="allow", reason=whitelist_check)
        
        # Step 3: Build request dictionary for detectors
        request_dict = self._build_request_dict(request) #defined below , it Transforms the WAFRequest into a standardized format that all security detectors can understand.
        
        # Step 4: Run security detectors
        detection_results = self._run_detectors(request_dict) # defined below , Runs ALL security checks against the request and collects results.
        
        # Step 5: Make final decision
        final_decision = self._make_decision(detection_results, request)
        
        # Step 6: Log decision
        self._log_decision(request, final_decision)
        
        # Step 7: Update statistics
        self._update_stats(final_decision, detection_results)
        
        return final_decision
    
    def _check_whitelists(self, request: WAFRequest) -> Optional[str]:
        """Check if request matches any whitelist rules"""
        
        # IP whitelist
        if request.client_ip in self.whitelist_ips:
            return f"ip_whitelisted:{request.client_ip}"
        
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
                # Parse URL-encoded form data: username=admin&password=123
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
            return results  # Don't waste time on further checks
        
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
        
        #  Add other detectors
        # if self.config_loader.is_detection_enabled("xss"):
        #     xss_patterns = self.rules.get('xss', [])
        #     xss_attack, xss_details = detect_xss(request_dict, xss_patterns)
        #     if xss_attack:
        #         results["detections"].append(...) 
        
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
        
        # Fallback - should never reach here
        return WAFResponse(allowed=True, action="allow", reason="fallback")
    
    def _log_decision(self, request: WAFRequest, decision: WAFResponse):
        """Log the WAF decision"""
        log_msg = (
            f"{request.method} {request.path} from {request.client_ip} - "
            f"Action: {decision.action} ({decision.reason})"
        )
        
        if decision.allowed:
            if "logged" in decision.reason:
                self.logger.warning(f"LOGGED: {log_msg}")
            else:
                self.logger.info(f"ALLOWED: {log_msg}")
        else:
            self.logger.warning(f"BLOCKED: {log_msg}")
    
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
        #self.state will be in this formate
        #self.stats = {
        #    "total_requests": 0,
        #   "blocked_requests": 0,
        #    "allowed_requests": 0,
        #    "challenges_issued": 0,
        #    "by_attack_type": {}  # Empty dictionary
        #}
    
    def reload_configuration(self) -> bool:
        """Reload all configuration and rules"""
        try:
            if self.config_loader.reload_all():
                self.config = self.config_loader.get_config()
                self.rules = self.config_loader.get_rules()
                self.whitelist_ips = self.config_loader.get_whitelist_ips()
                self.whitelist_paths = self.config_loader.get_whitelist_paths()
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
        
        return stats
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check of WAF components"""
        total_patterns = sum(len(patterns) for patterns in self.rules.values()) #How many security patterns are loaded across all rule categories.
        
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
            )
        }


# Singleton instance
_waf_instance = None

def get_waf() -> PyWAF:
    """Get or create singleton WAF instance"""
    global _waf_instance #_waf_instance is a global variable that stores the single WAF instance
    if _waf_instance is None:
        _waf_instance = PyWAF()
    return _waf_instance
#Ensures only ONE instance of PyWAF exists throughout your entire application.



# Self-test
if __name__ == "__main__":
    import logging
    from logging.handlers import RotatingFileHandler
    
    # ADD PROPER FILE LOGGING SETUP
    log_file = "logs/waf.log"
    
    # Create logs directory if it doesn't exist
    import os
    os.makedirs("logs", exist_ok=True)
    
    # Set up both console AND file logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            RotatingFileHandler(
                log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            ),
            logging.StreamHandler()  # Also show in console
        ]
    )
    
    print("Testing PyWAF Core Engine\n")
    print("="*60)
    
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
    print(f"Details: {result.details}")
    
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
    print(f"Details: {result.details}")
    
    # Test 4: Whitelisted IP
    print("\n[TEST 4] Whitelisted IP (127.0.0.1)")
    whitelist_request = WAFRequest(
        method="GET",
        path="/admin",
        headers={"user-agent": "curl/7.0"},
        client_ip="127.0.0.1",
        query_params={"action": "' DROP TABLE users--"}  # Attack, but whitelisted
    )
    
    result = waf.process_request(whitelist_request)
    print(f"Result: {result.action} - {result.reason}")
    print(f"Allowed: {result.allowed}")
    
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
    
    # Health check
    print("\n" + "="*60)
    print("🏥 Health Check:")
    health = waf.health_check()
    for key, value in health.items():
        print(f"  {key}: {value}")
    
    print("\n✅ WAF core engine test completed!")