# WebSocket-Fuzzer

WebSocket Fuzzer - Advanced Security Testing Tool
A stealthy and powerful WebSocket fuzzing tool designed for security professionals to test WebSocket implementations for various vulnerabilities.

Features
Multi-Vector Fuzzing: Tests for SQL injection, XSS, path traversal, command injection, XXE, buffer overflow, JSON injection, SSRF, and SSTI vulnerabilities

Stealth Mode: Implements random delays, request encoding, and realistic headers to evade detection

Smart Payload Encoding: Supports Base64, URL, Hex, and Zlib encoding techniques

JSON-Aware Fuzzing: Intelligently handles complex JSON structures

Response Analysis: Detects vulnerability indicators in server responses

Custom Headers Support: Add any headers needed for authentication or session management

Results Logging: Automatically saves findings to a file for later analysis

Installation
Clone or download this repository

Install required dependencies:

bash
pip install websockets asyncio
Usage
Basic Usage
bash
python websocket_fuzzer.py ws://example.com/websocket --template '{"message": "FUZZ_PAYLOAD"}'
Advanced Usage
bash
python websocket_fuzzer.py wss://secure.example.com/ws \
  --template '{"id": 123, "data": "FUZZ_PAYLOAD"}' \
  --delay 0.2 \
  --timeout 3.0 \
  --header "Authorization: Bearer token123" \
  --header "X-Custom-Header: value"
Command Line Options
Option	Description	Default
url	WebSocket URL (required)	-
--template	Message template with FUZZ_PAYLOAD placeholder	'FUZZ_PAYLOAD'
--no-stealth	Disable stealth mode (faster but more detectable)	Enabled
--delay	Delay between requests in seconds	0.1
--timeout	Response timeout in seconds	2.0
--header	Add custom headers (can be used multiple times)	-
Template Examples
Simple Text Message
bash
--template "FUZZ_PAYLOAD"
JSON Message
bash
--template '{"query": "FUZZ_PAYLOAD", "type": "search"}'
Nested JSON Structure
bash
--template '{"user": {"id": 123, "name": "FUZZ_PAYLOAD"}, "action": "update"}'
Payload Categories
The fuzzer tests for these vulnerability types:

SQL Injection: Common SQLi payloads for various databases

XSS: Multiple XSS vectors including script tags and event handlers

Path Traversal: Directory traversal techniques with various encodings

Command Injection: Shell command injection payloads

XXE: XML External Entity injection attacks

Prototype Pollution: JavaScript prototype manipulation

Buffer Overflow: Long strings and special characters

JSON Injection: Malicious JSON objects and operators

SSRF: Server-Side Request Forgery attempts

SSTI: Server-Side Template Injection payloads

Output
The tool provides real-time output showing:

Connection status

Sent messages

Server responses

Potential vulnerabilities detected

Findings are automatically saved to fuzz_findings.txt for later analysis.

Stealth Features
Random delays between requests

Realistic browser User-Agent string

Proper Origin header based on target URL

Multiple encoding techniques for payloads

WebSocket extension headers

Disclaimer
This tool is designed for security testing and educational purposes only. Only use it on systems you own or have explicit permission to test. Unauthorized testing against systems you don't own is illegal and unethical.

License
This project is provided for educational purposes only. Users are responsible for ensuring they have proper authorization before using this tool.
