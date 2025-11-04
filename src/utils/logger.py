# src/utils/logger.py
import logging
import json
import sys
import os
from datetime import datetime
from typing import Dict, Any, Optional
from logging.handlers import RotatingFileHandler

class WAFLogger:
    """
    Enhanced logging system for PyWAF with structured JSON logging
    and security event tracking
    """
    
    def __init__(self, name: str = "pywaf"):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Prevent duplicate handlers
        if self.logger.handlers:
            self.logger.handlers.clear()
        
        # Default format
        self.formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # JSON formatter for structured logging
        self.json_formatter = JSONFormatter()
        
        # Track security events
        self.security_events = []
        self.max_events = 1000  # Keep last 1000 events in memory
    
    def setup_file_logging(self, log_file: str = "logs/waf.log", 
                          max_size_mb: int = 100, 
                          backup_count: int = 5,
                          use_json: bool = False) -> None:
        """
        Setup file logging with rotation
        
        Args:
            log_file: Path to log file
            max_size_mb: Maximum log file size in MB
            backup_count: Number of backup files to keep
            use_json: Use JSON format instead of text
        """
        # Create logs directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        
        # Create rotating file handler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_size_mb * 1024 * 1024,  # Convert MB to bytes
            backupCount=backup_count,
            encoding='utf-8'
        )
        
        file_handler.setLevel(logging.INFO)
        formatter = self.json_formatter if use_json else self.formatter
        file_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
    
    def setup_console_logging(self, level: int = logging.INFO, use_json: bool = False) -> None:
        """
        Setup console logging
        
        Args:
            level: Logging level
            use_json: Use JSON format instead of text
        """
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        
        formatter = self.json_formatter if use_json else self.formatter
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(console_handler)
    
    def log_event(self, event_type: str, details: Dict[str, Any], 
                 level: str = "INFO", client_ip: str = "") -> None:
        """
        Log structured security event
        
        Args:
            event_type: Type of event (block, allow, challenge, etc.)
            details: Event details dictionary
            level: Log level (INFO, WARNING, ERROR)
            client_ip: Client IP address
        """
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "level": level,
            "client_ip": client_ip,
            **details
        }
        
        # Store in memory for dashboard
        self._store_security_event(log_data)
        
        # Log using appropriate method
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        
        if any(isinstance(h, RotatingFileHandler) for h in self.logger.handlers):
            # If using file logging with JSON formatter, log as string
            log_method(json.dumps(log_data, default=str))
        else:
            # For console logging, format nicely
            log_method(self._format_event_for_console(log_data))
    
    def _store_security_event(self, event: Dict[str, Any]) -> None:
        """Store security event in memory (for dashboard)"""
        self.security_events.append(event)
        
        # Keep only recent events
        if len(self.security_events) > self.max_events:
            self.security_events = self.security_events[-self.max_events:]
    
    def _format_event_for_console(self, event: Dict[str, Any]) -> str:
        """Format event for console output"""
        timestamp = event.get('timestamp', '')[:19]  # Shorten timestamp
        event_type = event.get('event_type', 'unknown')
        client_ip = event.get('client_ip', 'unknown')
        
        base_msg = f"{timestamp} [{event_type}] {client_ip}"
        
        # Add event-specific details
        if event_type == "request_blocked":
            return f"🚫 {base_msg} - {event.get('reason', '')} - {event.get('attack_type', '')}"
        elif event_type == "request_allowed":
            return f"✅ {base_msg} - Allowed"
        elif event_type == "challenge_issued":
            return f"🛡️ {base_msg} - Challenge required"
        elif event_type == "whitelist_bypass":
            return f"⚪ {base_msg} - Whitelisted ({event.get('reason', '')})"
        elif event_type == "rate_limit_exceeded":
            return f"🐌 {base_msg} - Rate limited"
        elif event_type == "config_reloaded":
            return f"🔄 {base_msg} - Configuration reloaded"
        else:
            return f"📝 {base_msg} - {event.get('message', '')}"
    
    # Convenience methods for common event types
    def log_request_blocked(self, reason: str, attack_type: str, 
                           client_ip: str, details: Dict[str, Any] = None) -> None:
        """Log blocked request"""
        event_details = {
            "reason": reason,
            "attack_type": attack_type,
            "action": "block",
            "details": details or {}
        }
        self.log_event("request_blocked", event_details, "WARNING", client_ip)
    
    def log_request_allowed(self, client_ip: str, path: str, 
                           detection_count: int = 0) -> None:
        """Log allowed request"""
        event_details = {
            "path": path,
            "detection_count": detection_count,
            "action": "allow"
        }
        level = "WARNING" if detection_count > 0 else "INFO"
        self.log_event("request_allowed", event_details, level, client_ip)
    
    def log_challenge_issued(self, client_ip: str, challenge_type: str, 
                            reason: str) -> None:
        """Log challenge issued"""
        event_details = {
            "challenge_type": challenge_type,
            "reason": reason,
            "action": "challenge"
        }
        self.log_event("challenge_issued", event_details, "INFO", client_ip)
    
    def log_whitelist_bypass(self, client_ip: str, reason: str, path: str = "") -> None:
        """Log whitelist bypass"""
        event_details = {
            "reason": reason,
            "path": path,
            "action": "whitelist"
        }
        self.log_event("whitelist_bypass", event_details, "INFO", client_ip)
    
    def log_rate_limit(self, client_ip: str, action: str, details: Dict[str, Any] = None) -> None:
        """Log rate limiting event"""
        event_details = {
            "action": action,
            "details": details or {}
        }
        self.log_event("rate_limit", event_details, "WARNING", client_ip)
    
    def log_config_change(self, component: str, action: str, details: Dict[str, Any] = None) -> None:
        """Log configuration change"""
        event_details = {
            "component": component,
            "action": action,
            "details": details or {}
        }
        self.log_event("config_change", event_details, "INFO", "")
    
    def get_recent_events(self, limit: int = 100, event_type: str = None) -> list:
        """Get recent security events (for dashboard)"""
        events = self.security_events[::-1]  # Reverse to get newest first
        
        if event_type:
            events = [e for e in events if e.get('event_type') == event_type]
        
        return events[:limit]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get logging statistics"""
        event_counts = {}
        for event in self.security_events:
            event_type = event.get('event_type', 'unknown')
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
        
        return {
            "total_events": len(self.security_events),
            "event_counts": event_counts,
            "max_events_stored": self.max_events
        }
    
    def clear_events(self) -> None:
        """Clear stored events (for testing)"""
        self.security_events.clear()


class JSONFormatter(logging.Formatter):
    """Custom formatter for JSON logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON string"""
        try:
            # If the message is already a JSON string, parse it first
            if isinstance(record.msg, str) and record.msg.strip().startswith('{'):
                log_data = json.loads(record.msg)
            else:
                log_data = {
                    "timestamp": self.formatTime(record),
                    "level": record.levelname,
                    "logger": record.name,
                    "message": record.getMessage(),
                    "module": record.module,
                    "line": record.lineno
                }
            
            # Add exception info if present
            if record.exc_info:
                log_data["exception"] = self.formatException(record.exc_info)
            
            return json.dumps(log_data, default=str)
            
        except (json.JSONDecodeError, TypeError):
            # Fallback to regular formatting if JSON fails
            return super().format(record)


# Singleton instance
_logger_instance = None

def get_waf_logger() -> WAFLogger:
    """Get or create singleton WAF logger instance"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = WAFLogger("pywaf")
        
        # Setup default logging (console only)
        _logger_instance.setup_console_logging()
    
    return _logger_instance

def setup_logging(log_file: str = None, use_json: bool = False, 
                 console_level: int = logging.INFO) -> WAFLogger:
    """
    Setup complete logging system
    
    Args:
        log_file: Path to log file (optional)
        use_json: Use JSON format for logging
        console_level: Console logging level
    
    Returns:
        Configured WAFLogger instance
    """
    logger = get_waf_logger()
    
    # Clear existing handlers
    logger.logger.handlers.clear()
    
    # Setup console logging
    logger.setup_console_logging(console_level, use_json)
    
    # Setup file logging if specified
    if log_file:
        logger.setup_file_logging(log_file, use_json=use_json)
    
    return logger


# Self-test
if __name__ == "__main__":
    print("🧪 Testing WAF Logger\n")
    
    # Test with console output only
    logger = setup_logging(console_level=logging.INFO)
    
    print("[TEST 1] Basic Logging")
    logger.logger.info("This is a regular info message")
    logger.logger.warning("This is a warning message")
    
    print("\n[TEST 2] Structured Security Events")
    logger.log_request_blocked(
        reason="sql_injection", 
        attack_type="sql_injection",
        client_ip="192.168.1.100",
        details={"pattern": "OR 1=1", "confidence": "high"}
    )
    
    logger.log_request_allowed(
        client_ip="192.168.1.101",
        path="/api/users",
        detection_count=0
    )
    
    logger.log_challenge_issued(
        client_ip="192.168.1.102",
        challenge_type="captcha",
        reason="suspicious_activity"
    )
    
    logger.log_whitelist_bypass(
        client_ip="127.0.0.1",
        reason="ip_whitelisted",
        path="/admin"
    )
    
    print("\n[TEST 3] Event Retrieval")
    recent_events = logger.get_recent_events(limit=3)
    print(f"Recent events: {len(recent_events)}")
    for event in recent_events:
        print(f"  - {event['event_type']} from {event['client_ip']}")
    
    print("\n[TEST 4] Statistics")
    stats = logger.get_stats()
    print(f"Total events: {stats['total_events']}")
    print(f"Event counts: {stats['event_counts']}")
    
    print("\n✅ Logger test completed!")