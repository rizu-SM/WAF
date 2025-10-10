# src/core/config_loader.py
import json
import yaml
import os
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

class ConfigLoader:
    """
    Centralized configuration manager for the WAF.
    Loads and manages detection rules, WAF settings, and whitelists.
    Implements singleton pattern for consistent state across the application.
    """
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(os.path.abspath(config_dir))  # Use absolute path
        self.logger = logging.getLogger(__name__)#Loggers are used to record messages (info, errors, warnings)
        #__name__ : Special Python variable that gives the current module name
        
        self._rules = {}
        self._config = {}
        self._whitelist_ips = []
        self._whitelist_paths = []  
        #_rules, _config, _whitelist: Internal storage for loaded data
        # Ensure config directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    def load_rules(self, rules_file: str = "waf_rules.json") -> Dict[str, List[str]]:
        """
        Load detection rules from JSON file
        
        Args:
            rules_file: Name of the rules file in config directory
            
        Returns:
            Dictionary of rule categories and patterns
            
        Example:
            {
                "sql_injection": ["pattern1", "pattern2"],
                "xss": ["pattern1", "pattern2"]
            }
        """
        rules_path = self.config_dir / rules_file
        
        try:
            with open(rules_path, 'r', encoding='utf-8') as f:
                self._rules = json.load(f)
            
            self.logger.info(f"Y Loaded rules from {rules_path}")
            self.logger.info(f"  Rule categories: {list(self._rules.keys())}")
            
            # Count total patterns
            total_patterns = sum(len(patterns) for patterns in self._rules.values())
            self.logger.info(f"  Total patterns: {total_patterns}")
            
            # Validate rules structure
            self._validate_rules()
            
            return self._rules
            
        except FileNotFoundError:
            self.logger.error(f" Rules file not found: {rules_path}")
            self.logger.info("Creating default rules file...")
            self._create_default_rules(rules_path)
            return self._rules  # Return newly created defaults
            
        except json.JSONDecodeError as e:
            self.logger.error(f" Invalid JSON in rules file: {e}")
            return {}
        except Exception as e:
            self.logger.error(f"Error loading rules: {e}")
            return {}
    
    def load_config(self, config_file: str = "waf_config.yaml") -> Dict[str, Any]:
        """
        Load WAF configuration from YAML file with defaults
        
        Args:
            config_file: Name of the config file in config directory
            
        Returns:
            Dictionary of configuration settings
        """
        config_path = self.config_dir / config_file
        
        # Enhanced default configuration
        default_config = {
            "waf": {
                "enabled": True,
                "mode": "block",  # block, log, challenge
                "max_payload_length": 2000,
                "backend_url": "http://localhost:8000",  #  ADD
                "timeout": 30  # ADD: Backend request timeout
            },
            "detection": {
                "sql_injection": {
                    "enabled": True,
                    "min_confidence": "medium"  # low, medium, high
                },
                "xss": {
                    "enabled": True,
                    "min_confidence": "medium"  #  Consistency
                },
                "path_traversal": {
                    "enabled": True,
                    "min_confidence": "medium"  #  Consistency
                }
            },
            "security": {
                "rate_limiting": {
                    "enabled": True,
                    "requests_per_minute": 100,
                    "block_duration": 300  # seconds
                },
                "bruteforce_protection": {
                    "enabled": True,
                    "max_attempts": 5,
                    "window_minutes": 10,
                    "lock_duration": 1800  # 30 min lock
                },
                "ip_blocking": {  # IP management
                    "enabled": True,
                    "auto_block": True,
                    "threshold": 10  # blocks before auto-ban
                }
            },
            "logging": {
                "level": "INFO",
                "file": "logs/waf.log",
                "format": "json",  # json or text
                "max_size_mb": 100,  # Log rotation
                "backup_count": 5  #  Keep 5 old logs
            }
        }
        
        # If config file doesn't exist, create it with defaults
        if not config_path.exists():
            self.logger.warning(f" Config file not found: {config_path}")
            self.logger.info("Creating default configuration file...")
            self._create_default_config(config_path, default_config)
            self._config = default_config
            return self._config
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                loaded_config = yaml.safe_load(f) or {}
            
            # Merge with defaults (deep merge)
            self._config = self._merge_configs(default_config, loaded_config)
            
            self.logger.info(f"Y Loaded configuration from {config_path}")
            return self._config
            
        except yaml.YAMLError as e:  #  ADD: Specific YAML error
            self.logger.error(f" Invalid YAML in config file: {e}")
            self._config = default_config
            return self._config
        except Exception as e:
            self.logger.error(f" Error loading config: {e}, using defaults")
            self._config = default_config
            return self._config
    
    def load_whitelist(self, whitelist_file: str = "whitelist.json") -> Dict[str, List[str]]:
        """
        Load IP and path whitelist from JSON file
        
        Args:
            whitelist_file: Name of the whitelist file in config directory
            
        Returns:
            Dictionary with 'ips' and 'paths' lists
        """
        whitelist_path = self.config_dir / whitelist_file
        
        default_whitelist = {
            "ips": [
                "127.0.0.1",
                "::1"
            ],
            "paths": [
                "/health",
                "/metrics",
                "/waf/stats"
            ]
        }
        
        if not whitelist_path.exists():
            self.logger.warning(f" Whitelist file not found: {whitelist_path}")
            self.logger.info("Creating default whitelist file...")
            self._create_default_whitelist(whitelist_path, default_whitelist)
            self._whitelist_ips = default_whitelist["ips"]
            self._whitelist_paths = default_whitelist["paths"]
            return default_whitelist
        
        try:
            with open(whitelist_path, 'r', encoding='utf-8') as f:
                whitelist_data = json.load(f)
            
            #  FIX: Handle both IPs and paths
            self._whitelist_ips = whitelist_data.get("ips", default_whitelist["ips"])
            self._whitelist_paths = whitelist_data.get("paths", default_whitelist["paths"])
            
            self.logger.info(f"Y Loaded {len(self._whitelist_ips)} whitelisted IPs")
            self.logger.info(f"Y Loaded {len(self._whitelist_paths)} whitelisted paths")
            
            return {
                "ips": self._whitelist_ips,
                "paths": self._whitelist_paths
            }
            
        except json.JSONDecodeError as e:
            self.logger.error(f" Invalid JSON in whitelist: {e}")
            self._whitelist_ips = default_whitelist["ips"]
            self._whitelist_paths = default_whitelist["paths"]
            return default_whitelist
        except Exception as e:
            self.logger.error(f" Error loading whitelist: {e}, using defaults")
            self._whitelist_ips = default_whitelist["ips"]
            self._whitelist_paths = default_whitelist["paths"]
            return default_whitelist
    
    def reload_all(self) -> bool:
        """Reload all configuration files"""
        try:
            self.load_rules()
            self.load_config()
            self.load_whitelist()
            self.logger.info("Y All configurations reloaded successfully")
            return True
        except Exception as e:
            self.logger.error(f" Error reloading configurations: {e}")
            return False
    
    # ADD: Getters for individual settings
    def get_rules(self, category: Optional[str] = None) -> Dict[str, List[str]]:
        """
        Get loaded rules, optionally filtered by category
        
        Args:
            category: Optional category name (e.g., "sql_injection")
            
        Returns:
            All rules or rules for specific category
        """
        if category:
            return {category: self._rules.get(category, [])}
        return self._rules
    
    def get_config(self, key_path: Optional[str] = None) -> Any:
        """
        Get configuration value, optionally by dot-separated path
        
        Args:
            key_path: Dot-separated path (e.g., "waf.backend_url")
            
        Returns:
            Full config or specific value
            
        Example:
            >>> loader.get_config("waf.mode")
            "block"
        """
        if not key_path:
            return self._config
        
        # Navigate nested dict using dot notation
        keys = key_path.split('.')
        value = self._config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value
    
    def get_whitelist_ips(self) -> List[str]:
        """Get whitelisted IP addresses"""
        return self._whitelist_ips
    
    def get_whitelist_paths(self) -> List[str]:
        """Get whitelisted paths"""
        return self._whitelist_paths
    
    def is_detection_enabled(self, detection_type: str) -> bool:
        """
        Check if a specific detection type is enabled
        
        Args:
            detection_type: e.g., "sql_injection", "xss"
            
        Returns:
            True if enabled, False otherwise
        """
        return self.get_config(f"detection.{detection_type}.enabled") or False
    
    def _validate_rules(self) -> None:
        """Validate rules structure"""
        if not isinstance(self._rules, dict):
            raise ValueError("Rules must be a dictionary")
        
        for category, patterns in self._rules.items():
            if not isinstance(patterns, list):
                raise ValueError(f"Rule category '{category}' must contain a list")
            
            for i, pattern in enumerate(patterns):
                if not isinstance(pattern, str):
                    raise ValueError(
                        f"Pattern #{i} in '{category}' must be a string, got {type(pattern)}"
                    )
    
    def _create_default_rules(self, rules_path: Path) -> None:
        """Create default rules file"""
        default_rules = {
            "sql_injection": [
                "(?i)(?:')\\s*or\\s*(?:'1'\\s*=\\s*'1|1\\s*=\\s*1)",
                "(?i)(?:union)\\s+(?:all\\s+)?select",
                "(?i)select\\s+.+\\s+from\\s+",
                "(?i)information_schema",
                "(?i)load_file\\s*\\(",
                "(?i)benchmark\\s*\\(",
                "(?i)(?:sleep|waitfor)\\s*\\(",
                "(?i)into\\s+outfile",
                "(?i)concat\\s*\\(",
                "(?i);\\s*(?:drop|delete|update)\\s+"
            ],
            "xss": [
                "(?i)<script[^>]*>.*?</script>",
                "(?i)javascript:",
                "(?i)on\\w+\\s*=",
                "(?i)<iframe",
                "(?i)<object",
                "(?i)eval\\s*\\(",
                "(?i)alert\\s*\\("
            ],
            "path_traversal": [
                "\\.\\.",
                "%2e%2e",
                "%252e%252e",
                "\\.\\.\\/",
                "\\.\\.\\\\",
                "..;/"
            ]
        }
        
        rules_path.parent.mkdir(parents=True, exist_ok=True)
        with open(rules_path, 'w', encoding='utf-8') as f:
            json.dump(default_rules, f, indent=2)
        
        self._rules = default_rules
        self.logger.info(f"Y Created default rules file: {rules_path}")
    
    def _create_default_config(self, config_path: Path, config: Dict[str, Any]) -> None:
        """Create default configuration file"""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, default_flow_style=False, indent=2, sort_keys=False)
        self.logger.info(f"Y Created default config file: {config_path}")
    
    def _create_default_whitelist(self, whitelist_path: Path, whitelist: Dict[str, List[str]]) -> None:
        """Create default whitelist file"""
        whitelist_path.parent.mkdir(parents=True, exist_ok=True)
        with open(whitelist_path, 'w', encoding='utf-8') as f:
            json.dump(whitelist, f, indent=2)
        self.logger.info(f"Y Created default whitelist file: {whitelist_path}")
    
    def _merge_configs(self, default: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two configuration dictionaries (user overrides default)"""
        result = default.copy()
        
        for key, value in user.items():
            if isinstance(value, dict) and key in result and isinstance(result[key], dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result


# Singleton instance for easy access
_config_loader = None

def get_config_loader(config_dir: str = "config") -> ConfigLoader:
    """Get or create singleton config loader instance"""
    global _config_loader
    if _config_loader is None:
        _config_loader = ConfigLoader(config_dir)
        # Auto-load all configs on first access
        _config_loader.load_rules()
        _config_loader.load_config()
        _config_loader.load_whitelist()
    return _config_loader

# Convenience functions
def load_rules(rules_file: str = "waf_rules.json") -> Dict[str, List[str]]:
    """Convenience function to load rules"""
    return get_config_loader().load_rules(rules_file)

def load_config(config_file: str = "waf_config.yaml") -> Dict[str, Any]:
    """Convenience function to load configuration"""
    return get_config_loader().load_config(config_file)

def load_whitelist(whitelist_file: str = "whitelist.json") -> Dict[str, List[str]]:
    """Convenience function to load whitelist"""
    return get_config_loader().load_whitelist(whitelist_file)


#  Self-test
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    print(" Testing ConfigLoader\n")
    
    loader = get_config_loader()
    
    print("\n Rules loaded:")
    for category, patterns in loader.get_rules().items():
        print(f"  {category}: {len(patterns)} patterns")
    
    print("\n  Configuration:")
    print(f"  WAF Mode: {loader.get_config('waf.mode')}")
    print(f"  Backend URL: {loader.get_config('waf.backend_url')}")
    print(f"  SQLi Detection: {'Y' if loader.is_detection_enabled('sql_injection') else 'N'}")
    
    print("\n Whitelist:")
    print(f"  IPs: {loader.get_whitelist_ips()}")
    print(f"  Paths: {loader.get_whitelist_paths()}")
    
    print("\n All tests passed!")


