package headers

import "github.com/cc1a2b/HHunter/engine"

func GetCORSMutations() []engine.Mutation {
	return []engine.Mutation{
		// Basic origin tests
		{Header: "Origin", Value: "https://evil.com", Category: "CORS", Impact: "CORS Misconfiguration - Arbitrary Origin"},
		{Header: "Origin", Value: "http://evil.com", Category: "CORS", Impact: "CORS Misconfiguration - HTTP Origin"},
		{Header: "Origin", Value: "null", Category: "CORS", Impact: "CORS Null Origin Bypass"},
		{Header: "Origin", Value: "file://", Category: "CORS", Impact: "CORS File Protocol Bypass"},
		{Header: "Origin", Value: "http://localhost", Category: "CORS", Impact: "CORS Localhost Bypass"},
		{Header: "Origin", Value: "http://127.0.0.1", Category: "CORS", Impact: "CORS Loopback Bypass"},
		{Header: "Origin", Value: "http://[::1]", Category: "CORS", Impact: "CORS IPv6 Loopback Bypass"},
		{Header: "Origin", Value: "http://0.0.0.0", Category: "CORS", Impact: "CORS Any Address Bypass"},

		// Subdomain / domain confusion
		{Header: "Origin", Value: "https://victim.com.evil.com", Category: "CORS", Impact: "CORS Subdomain Prefix Bypass"},
		{Header: "Origin", Value: "https://evilcom", Category: "CORS", Impact: "CORS TLD Missing Dot Bypass"},
		{Header: "Origin", Value: "https://evil-victim.com", Category: "CORS", Impact: "CORS Hyphen Subdomain Bypass"},
		{Header: "Origin", Value: "https://victimcom.evil.com", Category: "CORS", Impact: "CORS Suffix Bypass"},
		{Header: "Origin", Value: "https://victim.com.evil.com:443", Category: "CORS", Impact: "CORS Subdomain + Port Bypass"},
		{Header: "Origin", Value: "https://sub.victim.com", Category: "CORS", Impact: "CORS Subdomain Wildcard Test"},
		{Header: "Origin", Value: "https://evil.victim.com", Category: "CORS", Impact: "CORS Evil Subdomain Test"},
		{Header: "Origin", Value: "https://notarealvictim.com", Category: "CORS", Impact: "CORS Partial Match Test"},
		{Header: "Origin", Value: "https://victim.com@evil.com", Category: "CORS", Impact: "CORS Userinfo Bypass"},
		{Header: "Origin", Value: "https://victim.com%40evil.com", Category: "CORS", Impact: "CORS Encoded Userinfo Bypass"},
		{Header: "Origin", Value: "https://victim.com#evil.com", Category: "CORS", Impact: "CORS Fragment Bypass"},
		{Header: "Origin", Value: "https://victim.com%23evil.com", Category: "CORS", Impact: "CORS Encoded Fragment Bypass"},

		// Parser bypass
		{Header: "Origin", Value: "https://victim.com%60.evil.com", Category: "CORS", Impact: "CORS Backtick Parser Bypass"},
		{Header: "Origin", Value: "https://victim.com%09.evil.com", Category: "CORS", Impact: "CORS Tab Parser Bypass"},
		{Header: "Origin", Value: "https://victim.com%0d.evil.com", Category: "CORS", Impact: "CORS CR Parser Bypass"},
		{Header: "Origin", Value: "https://victim.com%0a.evil.com", Category: "CORS", Impact: "CORS LF Parser Bypass"},
		{Header: "Origin", Value: "https://victim.com\\.evil.com", Category: "CORS", Impact: "CORS Backslash Parser Bypass"},
		{Header: "Origin", Value: "https://victim.com%2eevil.com", Category: "CORS", Impact: "CORS Encoded Dot Bypass"},

		// Protocol-based bypass
		{Header: "Origin", Value: "data://evil.com", Category: "CORS", Impact: "CORS Data Protocol Bypass"},
		{Header: "Origin", Value: "javascript://evil.com", Category: "CORS", Impact: "CORS JavaScript Protocol Bypass"},
		{Header: "Origin", Value: "vbscript://evil.com", Category: "CORS", Impact: "CORS VBScript Protocol Bypass"},

		// Wildcard / reflection test
		{Header: "Origin", Value: "https://randomorigin123.com", Category: "CORS", Impact: "CORS Origin Reflection Test"},
		{Header: "Origin", Value: "https://anything.goes.here", Category: "CORS", Impact: "CORS Wildcard Acceptance Test"},

		// Preflight method tests
		{Header: "Access-Control-Request-Method", Value: "PUT", Category: "CORS", Impact: "CORS Preflight PUT"},
		{Header: "Access-Control-Request-Method", Value: "DELETE", Category: "CORS", Impact: "CORS Preflight DELETE"},
		{Header: "Access-Control-Request-Method", Value: "PATCH", Category: "CORS", Impact: "CORS Preflight PATCH"},
		{Header: "Access-Control-Request-Method", Value: "OPTIONS", Category: "CORS", Impact: "CORS Preflight OPTIONS"},
		{Header: "Access-Control-Request-Method", Value: "TRACE", Category: "CORS", Impact: "CORS Preflight TRACE"},
		{Header: "Access-Control-Request-Method", Value: "CONNECT", Category: "CORS", Impact: "CORS Preflight CONNECT"},

		// Preflight header tests
		{Header: "Access-Control-Request-Headers", Value: "X-Custom-Header", Category: "CORS", Impact: "CORS Custom Header Bypass"},
		{Header: "Access-Control-Request-Headers", Value: "Authorization", Category: "CORS", Impact: "CORS Auth Header Bypass"},
		{Header: "Access-Control-Request-Headers", Value: "X-CSRF-Token", Category: "CORS", Impact: "CORS CSRF Header Bypass"},
		{Header: "Access-Control-Request-Headers", Value: "Content-Type, Authorization, X-Requested-With", Category: "CORS", Impact: "CORS Multi-Header Bypass"},

		// Vary Origin test
		{Header: "Origin", Value: "", Category: "CORS", Impact: "CORS Empty Origin Test"},
		{Header: "Origin", Value: "https://evil.com\r\nAccess-Control-Allow-Origin: *", Category: "CORS", Impact: "CORS Header Injection"},
	}
}
