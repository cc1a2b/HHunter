package headers

import "github.com/cc1a2b/jshunter/engine"

func GetCORSMutations() []engine.Mutation {
	return []engine.Mutation{
		{Header: "Origin", Value: "https://evil.com", Category: "CORS", Impact: "CORS Misconfiguration"},
		{Header: "Origin", Value: "null", Category: "CORS", Impact: "CORS Null Origin Bypass"},
		{Header: "Origin", Value: "file://", Category: "CORS", Impact: "CORS File Origin Bypass"},
		{Header: "Origin", Value: "http://localhost", Category: "CORS", Impact: "CORS Localhost Bypass"},
		{Header: "Origin", Value: "http://127.0.0.1", Category: "CORS", Impact: "CORS Localhost Bypass"},
		{Header: "Origin", Value: "https://victim.com.evil.com", Category: "CORS", Impact: "CORS Subdomain Bypass"},
		{Header: "Origin", Value: "https://evilcom", Category: "CORS", Impact: "CORS TLD Bypass"},
		{Header: "Origin", Value: "https://victim.com%60.evil.com", Category: "CORS", Impact: "CORS Parser Bypass"},
		{Header: "Access-Control-Request-Method", Value: "PUT", Category: "CORS", Impact: "CORS Method Bypass"},
		{Header: "Access-Control-Request-Method", Value: "DELETE", Category: "CORS", Impact: "CORS Method Bypass"},
		{Header: "Access-Control-Request-Method", Value: "PATCH", Category: "CORS", Impact: "CORS Method Bypass"},
		{Header: "Access-Control-Request-Headers", Value: "X-Custom-Header", Category: "CORS", Impact: "CORS Header Bypass"},
		{Header: "Access-Control-Request-Headers", Value: "Authorization", Category: "CORS", Impact: "CORS Auth Header Bypass"},
	}
}
