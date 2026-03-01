package headers

import "github.com/cc1a2b/HHunter/engine"

func GetSecurityMutations() []engine.Mutation {
	return []engine.Mutation{
		// Content-Type manipulation for CSP bypass
		{Header: "Content-Type", Value: "text/html", Category: "Security", Impact: "Content-Type Override to HTML"},
		{Header: "Content-Type", Value: "application/javascript", Category: "Security", Impact: "Content-Type Override to JS"},
		{Header: "Content-Type", Value: "text/xml", Category: "Security", Impact: "Content-Type Override to XML"},
		{Header: "Content-Type", Value: "image/svg+xml", Category: "Security", Impact: "Content-Type Override to SVG"},
		{Header: "Content-Type", Value: "text/css", Category: "Security", Impact: "Content-Type Override to CSS"},
		{Header: "Content-Type", Value: "multipart/mixed", Category: "Security", Impact: "Content-Type Multipart Override"},

		// Accept header manipulation
		{Header: "Accept", Value: "text/html", Category: "Security", Impact: "Accept Override HTML"},
		{Header: "Accept", Value: "application/json", Category: "Security", Impact: "Accept Override JSON"},
		{Header: "Accept", Value: "application/xml", Category: "Security", Impact: "Accept Override XML"},
		{Header: "Accept", Value: "text/plain", Category: "Security", Impact: "Accept Override Plain Text"},
		{Header: "Accept", Value: "*/*", Category: "Security", Impact: "Accept Wildcard"},
		{Header: "Accept", Value: "application/xhtml+xml", Category: "Security", Impact: "Accept Override XHTML"},

		// X-Content-Type-Options bypass
		{Header: "X-Content-Type-Options", Value: "nosniff", Category: "Security", Impact: "X-Content-Type-Options Override"},

		// X-Frame-Options bypass
		{Header: "X-Frame-Options", Value: "ALLOWALL", Category: "Security", Impact: "X-Frame-Options Bypass"},
		{Header: "X-Frame-Options", Value: "ALLOW-FROM https://evil.com", Category: "Security", Impact: "X-Frame-Options Allow Evil Origin"},

		// HSTS bypass attempts
		{Header: "X-Forwarded-Proto", Value: "http", Category: "Security", Impact: "HSTS Bypass via Protocol Downgrade"},
		{Header: "X-Forwarded-Ssl", Value: "off", Category: "Security", Impact: "HSTS Bypass via SSL Off"},
		{Header: "X-Url-Scheme", Value: "http", Category: "Security", Impact: "HSTS Bypass via URL Scheme"},

		// Content-Security-Policy bypass
		{Header: "Content-Security-Policy", Value: "default-src *", Category: "Security", Impact: "CSP Override Wildcard"},
		{Header: "Content-Security-Policy-Report-Only", Value: "default-src *", Category: "Security", Impact: "CSP Report-Only Injection"},
		{Header: "X-Content-Security-Policy", Value: "allow *", Category: "Security", Impact: "Legacy CSP Override"},

		// Expect header
		{Header: "Expect", Value: "100-continue", Category: "Security", Impact: "Expect Header 100-Continue"},

		// Range header abuse
		{Header: "Range", Value: "bytes=0-0", Category: "Security", Impact: "Range Header Single Byte"},
		{Header: "Range", Value: "bytes=0-999999999", Category: "Security", Impact: "Range Header Oversized"},
		{Header: "Range", Value: "bytes=0-0,-1", Category: "Security", Impact: "Range Header Multi-Range"},
		{Header: "Range", Value: "bytes=-1", Category: "Security", Impact: "Range Header Negative"},

		// If-* conditional header abuse
		{Header: "If-Match", Value: "*", Category: "Security", Impact: "If-Match Wildcard"},
		{Header: "If-None-Match", Value: "*", Category: "Security", Impact: "If-None-Match Wildcard"},
		{Header: "If-Range", Value: "invalid", Category: "Security", Impact: "If-Range Invalid"},
		{Header: "If-Unmodified-Since", Value: "Thu, 01 Jan 2099 00:00:00 GMT", Category: "Security", Impact: "If-Unmodified-Since Future Date"},

		// Content-Disposition manipulation
		{Header: "Content-Disposition", Value: "attachment; filename=evil.html", Category: "Security", Impact: "Content-Disposition Override"},
		{Header: "Content-Disposition", Value: "inline; filename=evil.svg", Category: "Security", Impact: "Content-Disposition Inline SVG"},

		// DNT/tracking headers
		{Header: "DNT", Value: "0", Category: "Security", Impact: "Do-Not-Track Disabled"},
		{Header: "Sec-GPC", Value: "0", Category: "Security", Impact: "Global Privacy Control Disabled"},

		// Origin Isolation
		{Header: "Sec-Fetch-Site", Value: "same-origin", Category: "Security", Impact: "Sec-Fetch Spoof Same-Origin"},
		{Header: "Sec-Fetch-Site", Value: "none", Category: "Security", Impact: "Sec-Fetch Spoof None"},
		{Header: "Sec-Fetch-Mode", Value: "navigate", Category: "Security", Impact: "Sec-Fetch Mode Spoof Navigate"},
		{Header: "Sec-Fetch-Mode", Value: "no-cors", Category: "Security", Impact: "Sec-Fetch Mode Spoof No-CORS"},
		{Header: "Sec-Fetch-Dest", Value: "document", Category: "Security", Impact: "Sec-Fetch Dest Spoof Document"},
		{Header: "Sec-Fetch-Dest", Value: "empty", Category: "Security", Impact: "Sec-Fetch Dest Spoof Empty"},
		{Header: "Sec-Fetch-User", Value: "?1", Category: "Security", Impact: "Sec-Fetch User Spoof"},

		// Early hints / informational
		{Header: "X-DNS-Prefetch-Control", Value: "on", Category: "Security", Impact: "DNS Prefetch Control Override"},
		{Header: "X-Download-Options", Value: "noopen", Category: "Security", Impact: "Download Options Override"},
		{Header: "X-Permitted-Cross-Domain-Policies", Value: "all", Category: "Security", Impact: "Cross-Domain Policy Override"},
		{Header: "Referrer-Policy", Value: "no-referrer", Category: "Security", Impact: "Referrer Policy Override"},
		{Header: "Permissions-Policy", Value: "interest-cohort=()", Category: "Security", Impact: "Permissions Policy Override"},
	}
}
