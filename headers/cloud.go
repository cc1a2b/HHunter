package headers

import "github.com/cc1a2b/jshunter/engine"

func GetCloudMutations() []engine.Mutation {
	return []engine.Mutation{
		{Header: "CF-Connecting-IP", Value: "127.0.0.1", Category: "Cloud", Impact: "Cloudflare IP Bypass"},
		{Header: "CF-Connecting-IP", Value: "169.254.169.254", Category: "Cloud", Impact: "Cloud Metadata Access"},
		{Header: "True-Client-IP", Value: "127.0.0.1", Category: "Cloud", Impact: "Cloudflare IP Bypass"},
		{Header: "CF-RAY", Value: "test-CDN", Category: "Cloud", Impact: "CDN Detection"},
		{Header: "CF-IPCountry", Value: "XX", Category: "Cloud", Impact: "GeoIP Bypass"},
		{Header: "X-Amz-Server-Side-Encryption", Value: "AES256", Category: "Cloud", Impact: "AWS Header Injection"},
		{Header: "X-Amz-Request-Id", Value: "test", Category: "Cloud", Impact: "AWS Detection"},
		{Header: "X-Azure-Ref", Value: "test", Category: "Cloud", Impact: "Azure Detection"},
		{Header: "X-Azure-RequestId", Value: "test", Category: "Cloud", Impact: "Azure Detection"},
		{Header: "X-Google-Backend", Value: "test", Category: "Cloud", Impact: "GCP Detection"},
		{Header: "X-Cloud-Trace-Context", Value: "test", Category: "Cloud", Impact: "GCP Trace Injection"},
		{Header: "Fastly-Client-IP", Value: "127.0.0.1", Category: "Cloud", Impact: "Fastly IP Bypass"},
		{Header: "X-Akamai-Edgescape", Value: "test", Category: "Cloud", Impact: "Akamai Detection"},
		{Header: "X-CDN", Value: "test", Category: "Cloud", Impact: "Generic CDN Detection"},
		{Header: "X-Edge-Location", Value: "test", Category: "Cloud", Impact: "Edge Network Detection"},
		{Header: "X-Served-By", Value: "cache-test", Category: "Cloud", Impact: "CDN Server Detection"},
		{Header: "X-Backend-Server", Value: "internal", Category: "Cloud", Impact: "Backend Server Exposure"},
	}
}
