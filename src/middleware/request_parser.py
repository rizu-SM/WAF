# src/middleware/request_parser.py
import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
from http.client import parse_headers
'''is used to read and parse HTTP headers (the text part of a request or response that looks like this
Content-Type: text/html
Content-Length: 123
User-Agent: Mozilla/5.0
'''

from src.core.waf import WAFRequest

class HTTPRequestParser:
    """
    Parses raw HTTP requests into standardized WAFRequest objects.
    Handles various HTTP versions and formats.
    url:"get"
    /d//
    
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse_http_request(self, raw_request: bytes, client_ip: str = "") -> WAFRequest:
        """
        Parse raw HTTP request bytes into WAFRequest object
        
        Args:
            raw_request: Raw HTTP request bytes
            client_ip: Client IP address (if available)
            
        Returns:
            WAFRequest object with parsed components
        """
        try:
            # Decode bytes to string
            request_text = raw_request.decode('utf-8', errors='replace') # Convert raw bytes to string for easier parsing
            
            # Split into request line, headers, and body
            parts = request_text.split('\r\n\r\n', 1)
            header_section = parts[0]
            body = parts[1] if len(parts) > 1 else ""
            
            # Parse request line and headers
            lines = header_section.split('\r\n')
            request_line = lines[0]#take the first line
            header_lines = lines[1:]#take evrythink else
            
            # Parse request line
            method, path, http_version = self._parse_request_line(request_line)
            
            # Parse headers
            headers = self._parse_headers(header_lines)
            
            # Parse query parameters from URL
            query_params = self._parse_query_params(path)
            
            # Extract clean path (without query string)
            clean_path = self._extract_path(path)
            
            self.logger.debug(f"Parsed request: {method} {clean_path} from {client_ip}")
            
            return WAFRequest(
                method=method,
                path=clean_path,
                headers=headers,
                body=body,
                client_ip=client_ip,
                query_params=query_params
            )
            
        except Exception as e:
            self.logger.error(f"Failed to parse HTTP request: {e}")
            # Return a minimal valid request to avoid crashing
            return WAFRequest(
                method="GET",
                path="/",
                headers={},
                body="",
                client_ip=client_ip,
                query_params={}
            )
    
    def _parse_request_line(self, request_line: str) -> tuple[str, str, str]:
        """Parse HTTP request line: METHOD PATH HTTP/VERSION"""
        parts = request_line.split(' ', 2)
        if len(parts) < 3:
            raise ValueError(f"Invalid request line: {request_line}")
        
        method, path, http_version = parts
        return method.upper(), path, http_version
    
    def _parse_headers(self, header_lines: list[str]) -> Dict[str, str]:
        """Parse HTTP headers into dictionary"""
        headers = {}
        for line in header_lines:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        return headers
    
    def _parse_query_params(self, full_path: str) -> Dict[str, str]:
        """Extract query parameters from URL"""
        try:
            parsed_url = urlparse(full_path)
            query_params = {}
            
            if parsed_url.query:
                # Parse "key=value&key2=value2" into dictionary
                parsed = parse_qs(parsed_url.query, keep_blank_values=True)
                for key, values in parsed.items():
                    # Use first value for single values, keep list for multiple
                    query_params[key] = values[0] if len(values) == 1 else values
            
            return query_params
        except Exception as e:
            self.logger.warning(f"Failed to parse query params: {e}")
            return {}
    
    def _extract_path(self, full_path: str) -> str:
        """Extract clean path without query string"""
        try:
            parsed_url = urlparse(full_path)
            return parsed_url.path or "/"
        except:
            return full_path.split('?')[0]  # Fallback: remove everything after ?


# Singleton instance for easy access
_request_parser = None

def get_request_parser() -> HTTPRequestParser:
    """Get or create singleton request parser instance"""
    global _request_parser
    if _request_parser is None:
        _request_parser = HTTPRequestParser()
    return _request_parser

def parse_http_request(raw_request: bytes, client_ip: str = "") -> WAFRequest:
    """Convenience function to parse HTTP request"""
    return get_request_parser().parse_http_request(raw_request, client_ip)


class RequestParser:
    """
    Flask request adapter for WAF integration.
    Converts Flask request objects into WAFRequest objects.
    """
    
    @staticmethod
    def parse_request(flask_request) -> WAFRequest:
        """
        Parse Flask request object into WAFRequest
        
        Args:
            flask_request: Flask request object
            
        Returns:
            WAFRequest object
        """
        from flask import Request
        
        # Extract all data from Flask request
        method = flask_request.method.upper()
        path = flask_request.path
        
        # Get headers as dictionary
        headers = {k.lower(): v for k, v in flask_request.headers.items()}
        
        # Get query parameters
        query_params = {k: v for k, v in flask_request.args.items()}
        
        # Get body data (form data, JSON, or raw)
        body = ""
        if flask_request.is_json:
            import json
            body = json.dumps(flask_request.get_json(silent=True) or {})
        elif flask_request.form:
            body = "&".join([f"{k}={v}" for k, v in flask_request.form.items()])
        elif flask_request.data:
            body = flask_request.data.decode('utf-8', errors='replace')
        
        # Get client IP (handle proxies)
        client_ip = flask_request.headers.get('X-Forwarded-For', 
                    flask_request.headers.get('X-Real-IP', 
                    flask_request.remote_addr or '0.0.0.0'))
        
        if ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        
        return WAFRequest(
            method=method,
            path=path,
            headers=headers,
            body=body,
            client_ip=client_ip,
            query_params=query_params
        )


# Self-test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    print("🧪 Testing HTTP Request Parser\n")
    
    parser = get_request_parser()
    
    # Test 1: Simple GET request
    print("[TEST 1] Simple GET Request")
    raw_get = b"GET /api/users?page=1&limit=10 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    request = parser.parse_http_request(raw_get, "192.168.1.100")
    
    print(f"Method: {request.method}")          # GET
    print(f"Path: {request.path}")              # /api/users
    print(f"Query: {request.query_params}")     # {'page': '1', 'limit': '10'}
    print(f"Headers: {dict(list(request.headers.items())[:2])}")  # First 2 headers
    
    # Test 2: POST request with form data
    print("\n[TEST 2] POST Request with Form Data")
    raw_post = b"POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\nusername=admin&password=123"
    request = parser.parse_http_request(raw_post, "192.168.1.200")
    
    print(f"Method: {request.method}")          # POST
    print(f"Path: {request.path}")              # /login
    print(f"Body: {request.body}")              # username=admin&password=123
    print(f"Content-Type: {request.headers.get('content-type')}")
    
    # Test 3: SQL injection in query
    print("\n[TEST 3] SQL Injection in Query")
    raw_sql = b"GET /search?q=' OR 1=1-- HTTP/1.1\r\nHost: example.com\r\nUser-Agent: sqlmap\r\n\r\n"
    request = parser.parse_http_request(raw_sql, "1.2.3.4")
    
    print(f"Path: {request.path}")              # /search
    print(f"Query: {request.query_params}")     # {'q': "' OR 1=1--"}
    
    # Test 4: Malformed request (should handle gracefully)
    print("\n[TEST 4] Malformed Request")
    raw_bad = b"INVALID REQUEST LINE\r\nHeader: value\r\n\r\n"
    request = parser.parse_http_request(raw_bad, "5.6.7.8")
    
    print(f"Method: {request.method}")          # GET (fallback)
    print(f"Path: {request.path}")              # / (fallback)
    
    print("\n✅ Request parser test completed!")