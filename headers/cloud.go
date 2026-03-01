package headers

import "github.com/cc1a2b/HHunter/engine"

func GetCloudMutations() []engine.Mutation {
	return []engine.Mutation{
		// Cloudflare
		{Header: "CF-Connecting-IP", Value: "127.0.0.1", Category: "Cloud", Impact: "Cloudflare IP Bypass - Loopback"},
		{Header: "CF-Connecting-IP", Value: "169.254.169.254", Category: "Cloud", Impact: "Cloudflare IP Bypass - Metadata"},
		{Header: "CF-Connecting-IP", Value: "10.0.0.1", Category: "Cloud", Impact: "Cloudflare IP Bypass - Internal"},
		{Header: "True-Client-IP", Value: "127.0.0.1", Category: "Cloud", Impact: "True-Client-IP Bypass - Loopback"},
		{Header: "True-Client-IP", Value: "169.254.169.254", Category: "Cloud", Impact: "True-Client-IP Bypass - Metadata"},
		{Header: "CF-RAY", Value: "test-CDN-bypass", Category: "Cloud", Impact: "CF-RAY CDN Detection/Bypass"},
		{Header: "CF-IPCountry", Value: "XX", Category: "Cloud", Impact: "CF GeoIP Bypass - XX"},
		{Header: "CF-IPCountry", Value: "T1", Category: "Cloud", Impact: "CF GeoIP Bypass - Tor"},
		{Header: "CF-IPCountry", Value: "US", Category: "Cloud", Impact: "CF GeoIP Bypass - US"},
		{Header: "CF-Visitor", Value: "{\"scheme\":\"https\"}", Category: "Cloud", Impact: "CF Visitor Scheme Override"},
		{Header: "CF-Worker", Value: "true", Category: "Cloud", Impact: "CF Worker Detection"},
		{Header: "CDN-Loop", Value: "cloudflare", Category: "Cloud", Impact: "CDN Loop Detection"},

		// AWS
		{Header: "X-Amz-Server-Side-Encryption", Value: "AES256", Category: "Cloud", Impact: "AWS SSE Header Injection"},
		{Header: "X-Amz-Request-Id", Value: "test-injection", Category: "Cloud", Impact: "AWS Request ID Injection"},
		{Header: "X-Amz-Security-Token", Value: "test", Category: "Cloud", Impact: "AWS Security Token Probe"},
		{Header: "X-Amz-Cf-Id", Value: "test", Category: "Cloud", Impact: "AWS CloudFront ID Injection"},
		{Header: "X-Amz-Date", Value: "20200101T000000Z", Category: "Cloud", Impact: "AWS Date Header Injection"},
		{Header: "X-Amz-Content-Sha256", Value: "UNSIGNED-PAYLOAD", Category: "Cloud", Impact: "AWS Unsigned Payload"},
		{Header: "X-Amz-Invocation-Type", Value: "Event", Category: "Cloud", Impact: "AWS Lambda Invocation Type"},
		{Header: "X-Amz-Target", Value: "DynamoDB_20120810.ListTables", Category: "Cloud", Impact: "AWS DynamoDB Target Injection"},

		// Azure
		{Header: "X-Azure-Ref", Value: "test-bypass", Category: "Cloud", Impact: "Azure Reference Injection"},
		{Header: "X-Azure-RequestId", Value: "test-injection", Category: "Cloud", Impact: "Azure Request ID Injection"},
		{Header: "X-Azure-DebugInfo", Value: "1", Category: "Cloud", Impact: "Azure Debug Info Probe"},
		{Header: "X-Azure-ClientIP", Value: "127.0.0.1", Category: "Cloud", Impact: "Azure Client IP Override"},
		{Header: "X-Azure-SocketIP", Value: "127.0.0.1", Category: "Cloud", Impact: "Azure Socket IP Override"},
		{Header: "X-Azure-FDID", Value: "test", Category: "Cloud", Impact: "Azure Front Door ID Injection"},
		{Header: "X-FD-HealthProbe", Value: "1", Category: "Cloud", Impact: "Azure FD Health Probe Spoof"},

		// GCP
		{Header: "X-Google-Backend", Value: "test-internal", Category: "Cloud", Impact: "GCP Backend Injection"},
		{Header: "X-Cloud-Trace-Context", Value: "test/1;o=1", Category: "Cloud", Impact: "GCP Trace Context Injection"},
		{Header: "X-Google-GFE-Request-Trace", Value: "test", Category: "Cloud", Impact: "GCP GFE Request Trace"},
		{Header: "X-AppEngine-Country", Value: "US", Category: "Cloud", Impact: "GAE Country Bypass"},
		{Header: "X-AppEngine-City", Value: "internal", Category: "Cloud", Impact: "GAE City Injection"},
		{Header: "X-AppEngine-CityLatLong", Value: "0,0", Category: "Cloud", Impact: "GAE Location Injection"},
		{Header: "X-AppEngine-Region", Value: "us", Category: "Cloud", Impact: "GAE Region Injection"},
		{Header: "X-AppEngine-Cron", Value: "true", Category: "Cloud", Impact: "GAE Cron Job Spoof"},
		{Header: "X-AppEngine-QueueName", Value: "default", Category: "Cloud", Impact: "GAE Task Queue Spoof"},
		{Header: "X-AppEngine-TaskName", Value: "test", Category: "Cloud", Impact: "GAE Task Name Spoof"},

		// Fastly
		{Header: "Fastly-Client-IP", Value: "127.0.0.1", Category: "Cloud", Impact: "Fastly IP Bypass - Loopback"},
		{Header: "Fastly-Client-IP", Value: "169.254.169.254", Category: "Cloud", Impact: "Fastly IP Bypass - Metadata"},
		{Header: "Fastly-Debug", Value: "1", Category: "Cloud", Impact: "Fastly Debug Mode"},
		{Header: "Fastly-SSL", Value: "1", Category: "Cloud", Impact: "Fastly SSL Override"},
		{Header: "Fastly-FF", Value: "test", Category: "Cloud", Impact: "Fastly Feature Flag Injection"},

		// Akamai
		{Header: "X-Akamai-Edgescape", Value: "test-internal", Category: "Cloud", Impact: "Akamai Edgescape Injection"},
		{Header: "Akamai-Origin-Hop", Value: "1", Category: "Cloud", Impact: "Akamai Origin Hop Override"},
		{Header: "X-Akamai-Config-Log-Detail", Value: "true", Category: "Cloud", Impact: "Akamai Config Log Detail"},

		// Generic CDN / Load Balancer
		{Header: "X-CDN", Value: "bypass", Category: "Cloud", Impact: "Generic CDN Bypass"},
		{Header: "X-Edge-Location", Value: "internal", Category: "Cloud", Impact: "Edge Location Injection"},
		{Header: "X-Served-By", Value: "cache-internal", Category: "Cloud", Impact: "CDN Server Injection"},
		{Header: "X-Backend-Server", Value: "internal-server", Category: "Cloud", Impact: "Backend Server Exposure"},
		{Header: "X-Timer", Value: "test", Category: "Cloud", Impact: "CDN Timer Injection"},
		{Header: "X-Varnish", Value: "test", Category: "Cloud", Impact: "Varnish Cache Injection"},

		// Kubernetes / Service Mesh
		{Header: "X-Request-Id", Value: "test-internal", Category: "Cloud", Impact: "K8s Request ID Injection"},
		{Header: "X-Envoy-Peer-Metadata", Value: "test", Category: "Cloud", Impact: "Envoy Peer Metadata Injection"},
		{Header: "X-Envoy-Peer-Metadata-Id", Value: "test", Category: "Cloud", Impact: "Envoy Peer Metadata ID"},
		{Header: "X-Envoy-Attempt-Count", Value: "0", Category: "Cloud", Impact: "Envoy Attempt Count Override"},
		{Header: "X-Envoy-External-Address", Value: "127.0.0.1", Category: "Cloud", Impact: "Envoy External Address Override"},
		{Header: "X-Envoy-Internal", Value: "true", Category: "Cloud", Impact: "Envoy Internal Request Spoof"},
		{Header: "X-Envoy-Decorator-Operation", Value: "internal", Category: "Cloud", Impact: "Envoy Decorator Override"},
		{Header: "X-Envoy-Upstream-Service-Time", Value: "0", Category: "Cloud", Impact: "Envoy Upstream Time Override"},
		{Header: "X-Istio-Attributes", Value: "test", Category: "Cloud", Impact: "Istio Attributes Injection"},
		{Header: "X-B3-TraceId", Value: "test", Category: "Cloud", Impact: "Zipkin Trace ID Injection"},
		{Header: "X-B3-SpanId", Value: "test", Category: "Cloud", Impact: "Zipkin Span ID Injection"},
		{Header: "X-B3-Sampled", Value: "1", Category: "Cloud", Impact: "Zipkin Sampling Override"},
		{Header: "Traceparent", Value: "00-test-test-01", Category: "Cloud", Impact: "W3C Trace Context Injection"},

		// Traefik
		{Header: "X-Traefik-Frontend", Value: "internal", Category: "Cloud", Impact: "Traefik Frontend Override"},
		{Header: "X-Traefik-Backend", Value: "internal", Category: "Cloud", Impact: "Traefik Backend Override"},

		// Nginx specific
		{Header: "X-Accel-Redirect", Value: "/internal/admin", Category: "Cloud", Impact: "Nginx X-Accel-Redirect Bypass"},
		{Header: "X-Accel-Buffering", Value: "no", Category: "Cloud", Impact: "Nginx Accel Buffering Off"},
		{Header: "X-Accel-Charset", Value: "utf-8", Category: "Cloud", Impact: "Nginx Accel Charset Override"},
		{Header: "X-Accel-Expires", Value: "0", Category: "Cloud", Impact: "Nginx Accel Expires Zero"},
	}
}
