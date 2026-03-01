package headers

import "github.com/cc1a2b/hhunter/engine"

func GetCacheMutations() []engine.Mutation {
	return []engine.Mutation{
		// Cache poisoning via host headers
		{Header: "X-Forwarded-Host", Value: "evil.com", Category: "Cache", Impact: "Cache Poisoning via X-Forwarded-Host"},
		{Header: "X-Host", Value: "evil.com", Category: "Cache", Impact: "Cache Poisoning via X-Host"},
		{Header: "Host", Value: "evil.com", Category: "Cache", Impact: "Host Header Cache Poisoning"},
		{Header: "X-Forwarded-Server", Value: "evil.com", Category: "Cache", Impact: "Cache Poisoning via X-Forwarded-Server"},
		{Header: "X-HTTP-Host-Override", Value: "evil.com", Category: "Cache", Impact: "Cache Poisoning via Host Override"},
		{Header: "X-Original-Host", Value: "evil.com", Category: "Cache", Impact: "Cache Poisoning via X-Original-Host"},
		{Header: "X-Backend-Host", Value: "evil.com", Category: "Cache", Impact: "Cache Poisoning via X-Backend-Host"},
		{Header: "X-Proxy-Host", Value: "evil.com", Category: "Cache", Impact: "Cache Poisoning via X-Proxy-Host"},

		// Cache deception
		{Header: "X-Original-URL", Value: "/admin", Category: "Cache", Impact: "Cache Deception - Admin Path"},
		{Header: "X-Original-URL", Value: "/api/user/profile", Category: "Cache", Impact: "Cache Deception - Profile Path"},
		{Header: "X-Original-URL", Value: "/account/settings", Category: "Cache", Impact: "Cache Deception - Account Settings"},
		{Header: "X-Rewrite-URL", Value: "/admin", Category: "Cache", Impact: "Cache Deception via URL Rewrite"},
		{Header: "X-Rewrite-URL", Value: "/api/v1/users", Category: "Cache", Impact: "Cache Deception via API Rewrite"},
		{Header: "X-Original-URL", Value: "//evil.com", Category: "Cache", Impact: "Open Redirect via Cache"},

		// Protocol downgrade
		{Header: "X-Forwarded-Scheme", Value: "http", Category: "Cache", Impact: "Protocol Downgrade Cache Poisoning"},
		{Header: "X-Forwarded-Scheme", Value: "nothttps", Category: "Cache", Impact: "Protocol Confusion Cache Poisoning"},
		{Header: "X-Forwarded-Proto", Value: "http", Category: "Cache", Impact: "Proto Downgrade Cache Poisoning"},
		{Header: "X-Forwarded-Ssl", Value: "off", Category: "Cache", Impact: "SSL Off Cache Poisoning"},

		// Cache control manipulation
		{Header: "Pragma", Value: "no-cache", Category: "Cache", Impact: "Cache Bypass via Pragma"},
		{Header: "Cache-Control", Value: "no-cache, no-store, must-revalidate", Category: "Cache", Impact: "Cache Bypass - Full No-Cache"},
		{Header: "Cache-Control", Value: "max-age=0", Category: "Cache", Impact: "Cache Bypass - Max-Age Zero"},
		{Header: "Cache-Control", Value: "s-maxage=0", Category: "Cache", Impact: "Cache Bypass - S-MaxAge Zero"},
		{Header: "Cache-Control", Value: "no-transform", Category: "Cache", Impact: "Cache No Transform"},
		{Header: "Cache-Control", Value: "only-if-cached", Category: "Cache", Impact: "Cache Only-If-Cached"},
		{Header: "Cache-Control", Value: "max-stale=99999999", Category: "Cache", Impact: "Cache Max Stale"},
		{Header: "Cache-Control", Value: "min-fresh=0", Category: "Cache", Impact: "Cache Min Fresh Zero"},
		{Header: "Cache-Control", Value: "private", Category: "Cache", Impact: "Cache Private Directive"},
		{Header: "Cache-Control", Value: "public", Category: "Cache", Impact: "Cache Public Directive"},

		// ETag / conditional request manipulation
		{Header: "If-None-Match", Value: "invalid-etag", Category: "Cache", Impact: "Cache Validation Bypass - Invalid ETag"},
		{Header: "If-None-Match", Value: "*", Category: "Cache", Impact: "Cache Validation Bypass - Wildcard ETag"},
		{Header: "If-None-Match", Value: "W/\"weak-etag\"", Category: "Cache", Impact: "Cache Validation Bypass - Weak ETag"},
		{Header: "If-Modified-Since", Value: "Mon, 01 Jan 1970 00:00:00 GMT", Category: "Cache", Impact: "Cache Validation Bypass - Epoch Date"},
		{Header: "If-Modified-Since", Value: "Thu, 01 Jan 2099 00:00:00 GMT", Category: "Cache", Impact: "Cache Validation Bypass - Future Date"},

		// CDN / Surrogate cache headers
		{Header: "Surrogate-Control", Value: "max-age=0", Category: "Cache", Impact: "CDN Surrogate Cache Bypass"},
		{Header: "Surrogate-Control", Value: "no-store", Category: "Cache", Impact: "CDN Surrogate No-Store"},
		{Header: "Surrogate-Capability", Value: "abc=\"ESI/1.0\"", Category: "Cache", Impact: "ESI Injection Capability"},
		{Header: "X-Cache", Value: "hit", Category: "Cache", Impact: "Cache Status Manipulation - Hit"},
		{Header: "X-Cache", Value: "miss", Category: "Cache", Impact: "Cache Status Manipulation - Miss"},
		{Header: "X-Cache-Status", Value: "BYPASS", Category: "Cache", Impact: "Cache Status Bypass"},
		{Header: "CDN-Cache-Control", Value: "no-store", Category: "Cache", Impact: "CDN Cache Control Override"},
		{Header: "Cloudflare-CDN-Cache-Control", Value: "no-store", Category: "Cache", Impact: "Cloudflare Cache Control Override"},
		{Header: "Fastly-Debug", Value: "1", Category: "Cache", Impact: "Fastly Debug Mode"},

		// Vary header exploitation
		{Header: "Accept-Encoding", Value: "gzip, deflate, br, zstd", Category: "Cache", Impact: "Cache Key Accept-Encoding Variant"},
		{Header: "Accept-Encoding", Value: "invalid-encoding", Category: "Cache", Impact: "Cache Key Invalid Encoding"},
		{Header: "Accept-Language", Value: "en-US,en;q=0.9,xx;q=0.8", Category: "Cache", Impact: "Cache Key Accept-Language Variant"},
		{Header: "Accept", Value: "application/json", Category: "Cache", Impact: "Cache Key Accept Variant"},
		{Header: "Accept", Value: "text/html", Category: "Cache", Impact: "Cache Key HTML Accept Variant"},

		// X-Forwarded-Port cache key manipulation
		{Header: "X-Forwarded-Port", Value: "443", Category: "Cache", Impact: "Cache Key Port Variant 443"},
		{Header: "X-Forwarded-Port", Value: "80", Category: "Cache", Impact: "Cache Key Port Variant 80"},
		{Header: "X-Forwarded-Port", Value: "8443", Category: "Cache", Impact: "Cache Key Port Variant 8443"},

		// Edge Side Includes (ESI) probing
		{Header: "X-ESI", Value: "true", Category: "Cache", Impact: "ESI Processing Probe"},
		{Header: "Surrogate-Control", Value: "content=\"ESI/1.0\"", Category: "Cache", Impact: "ESI Content Negotiation"},
	}
}
