# HHunter

<div align="center">

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/release/cc1a2b/HHunter.svg)](https://github.com/cc1a2b/HHunter/releases)
[![GitHub stars](https://img.shields.io/github/stars/cc1a2b/HHunter)](https://github.com/cc1a2b/HHunter/stargazers)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/cc1a2b/HHunter/releases)

**Advanced HTTP Header Vulnerability Scanner**

*1100+ mutations across 22 attack categories with OOB detection, adaptive scanning, and evidence-based reporting for security professionals*

</div>

## About

**HHunter** is an advanced HTTP header security testing engine built for penetration testers and bug bounty hunters. It discovers real vulnerabilities through intelligent header mutation and differential response analysis — not just information gathering. With 1100+ attack mutations, out-of-band blind vulnerability detection, technology-adaptive scanning, and chained multi-header attacks, HHunter finds what other tools miss.

<div align="center">

<!-- <img alt="HHunter Demo Screenshot" src="https://github.com/user-attachments/assets/placeholder" width="100%"> -->

*HHunter v0.1 — Finding real vulnerabilities through header mutation analysis*

</div>

---

## Table of Contents

- [About](#about)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Command Reference](#command-reference)
- [Advanced Usage](#advanced-usage)
- [Detection Categories](#detection-categories)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

---

## Features

### Core Capabilities
- **Authentication Bypass**: JWT none/kid/jku attacks, token manipulation, role injection, cloud identity spoofing (198 mutations)
- **SSRF via Headers**: IMDSv2 bypass, Azure managed identity tokens, GCP metadata, K8s API/secrets, 50+ internal services (198 mutations)
- **Injection Engine**: SSTI per engine (Jinja2/Twig/Thymeleaf/Freemarker/Velocity/Pebble), Log4Shell 20+ WAF bypasses, blind SQLi, OGNL/EL (148 mutations)
- **CORS Exploitation**: Origin reflection, null origin, subdomain bypass, method/header expansion detection
- **Cache Poisoning**: Host header injection, X-Forwarded-Host, cache key manipulation, CDN bypass
- **OOB Detection**: Built-in callback server for blind SSRF, blind XSS, blind Log4Shell, blind RCE confirmation
- **Chained Attacks**: Multi-header combo mutations across 7 strategic pairing categories

### Intelligent Detection Engine
> **Evidence-based analysis with zero false positive design**

- **Differential Analysis**: Statistical baseline profiling (multi-sample) with semantic response comparison
- **Response Similarity**: LCS-based body comparison, structural HTML/JSON matching, header set analysis — not just hash comparison
- **Technology Adaptive**: Fingerprints server/language/framework/WAF, then prioritizes relevant mutations (PHP payloads for PHP targets, etc.)
- **Context-Aware Reflection**: Distinguishes dangerous reflection contexts (JS, HTML attr, unescaped) from safe ones (JSON strings, CDN headers)
- **Finding Deduplication**: Groups findings by root cause (header family + impact type), keeps highest-confidence instance, merges alternate triggers

### Professional HTTP & Networking Suite
<details>
<summary><strong>Enterprise-Grade Network Configuration</strong></summary>

**Request Configuration:**
- **Custom Headers** (`-H`): Repeatable custom HTTP headers for authenticated testing
- **Request Body** (`-d`): POST/PUT body data with Content-Type control (`-ct`)
- **Raw Request Import** (`--raw`): Import requests directly from Burp Suite
- **Cookie Support** (`-b`): Session cookies for accessing protected endpoints
- **HTTP Methods** (`-m`): Test any HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)

**Performance & Control:**
- **Concurrency** (`-w`): Adjustable worker threads (default: 30)
- **Rate Limiting** (`-r`): Request delay in milliseconds to avoid detection
- **Timeouts** (`-t`): Configurable request timeout (default: 30s)
- **Redirect Control** (`-fr`): Follow or block HTTP redirects

**Proxy & Stealth:**
- **Proxy Support** (`--proxy-url`): Full Burp Suite and proxy tool integration (HTTP/HTTPS/SOCKS)
- **WAF Evasion** (`--waf-evasion`): Header case randomization and evasion techniques
- **Stealth Mode** (`--stealth`): Slower, more evasive scanning approach

> **Example**: `hhunter -u https://target.com/api --auth --proxy --proxy-url http://127.0.0.1:8080 -H "Authorization: Bearer token"`

</details>

### Out-of-Band (OOB) Detection
<details>
<summary><strong>Blind Vulnerability Confirmation via Callback Server</strong></summary>

HHunter includes a built-in OOB callback server that confirms blind vulnerabilities with high confidence:

- **Blind SSRF**: HTTP/HTTPS/DNS-based callbacks for every SSRF mutation
- **Blind Log4Shell**: LDAP/LDAPS/DNS/RMI OOB + obfuscated bypass variants + env variable exfiltration
- **Blind XXE**: SYSTEM entity and parameter entity OOB callbacks
- **Blind SSTI**: Per-engine OOB (Java curl, Jinja2 popen, Twig system)
- **Blind RCE**: curl/wget/nslookup/PowerShell callbacks + whoami exfiltration
- **Blind XSS**: Persistent XSS detection via img src and script src OOB

**How it works:**
1. Start with `--oob --oob-url http://your-vps:8888`
2. HHunter injects unique interaction IDs into each payload
3. When a target processes a blind payload, it calls back to your server
4. HHunter correlates the callback to the exact mutation → confirmed finding (0.95 confidence)

> **Example**: `hhunter -u https://target.com --full --oob --oob-url http://your-vps:8888 --oob-wait 30`

</details>

### Attack Categories (22 Total)
<details>
<summary><strong>Comprehensive Header-Based Attack Vectors</strong></summary>

**Core Categories:**
| Flag | Category | Description |
|------|----------|-------------|
| `--auth` | Authentication | JWT bypass, token manipulation, role injection, IDOR, CSRF bypass |
| `--proxy` | Proxy Trust | IP spoofing, X-Forwarded-For, internal network access |
| `--cors` | CORS | Origin reflection, null origin, subdomain bypass |
| `--cache` | Cache Poisoning | Host injection, cache key manipulation, CDN bypass |
| `--override` | Method Override | HTTP verb tampering, URL rewrite, path override |
| `--cloud` | Cloud/CDN | AWS/Azure/GCP/K8s header injection |
| `--debug` | Debug Exposure | Debug mode activation, feature flags, stack traces |

**Advanced Categories:**
| Flag | Category | Description |
|------|----------|-------------|
| `--injection` | Injection | XSS, SSTI (9 engines), Log4Shell (20+ bypasses), SQLi (5 DBs), OGNL, NoSQL, LDAP |
| `--ssrf` | SSRF | Cloud metadata (IMDSv2, Azure MI, GCP), K8s, Docker, 50+ internal services |
| `--smuggling` | Smuggling | CL-TE, TE-CL, trailer injection |
| `--hopbyhop` | Hop-by-Hop | Header stripping attacks |
| `--ratelimit` | Rate Limit | Rate limit bypass techniques |
| `--security` | Security Headers | CSP, HSTS, X-Frame-Options manipulation |
| `--websocket` | WebSocket | WebSocket/gRPC/GraphQL upgrade probes |
| `--jwt` | JWT | alg:none, kid traversal, jku/x5u poisoning, weak secrets |
| `--crlf` | CRLF | Response splitting, header injection |
| `--cookie` | Cookie | Fixation, tossing, overflow attacks |
| `--content-type` | Content-Type | MIME confusion, WAF bypass |
| `--redirect` | Redirect | Open redirect via header manipulation |
| `--protocol` | Protocol | h2c smuggling, HTTP/2 upgrade |
| `--encoding` | Encoding | Charset attacks, WAF bypass, Range abuse |
| `--gateway` | Gateway | Kong, Envoy, Traefik, API gateway bypass |

> **Full scan**: `hhunter -u https://target.com --full` runs all 22 categories + audit + recon + verify + chain

</details>

### Professional Reporting & Export
<details>
<summary><strong>Enterprise-Grade Output & CI/CD Integration</strong></summary>

**Output Formats:**
- **Console Display**: Color-coded findings with severity badges, confidence scores, evidence details, and remediation
- **JSON Export** (`-o`): Structured output with full scan stats, findings, evidence, and audit results
- **HTML Report** (`--report`): Self-contained dark-themed report with expandable findings, stats grid, and severity breakdown
- **SARIF Report** (`--sarif`): SARIF 2.1.0 JSON for GitHub Code Scanning, Azure DevOps, and CI/CD pipelines

**Matchers & Filters:**
- **Match Status** (`-ms`): Only process specific status codes (e.g., `200,302`)
- **Filter Status** (`-fs`): Exclude status codes (e.g., `404,500`)
- **Match/Filter Size**: Process or exclude responses by byte size

**Result Management:**
- **Differential Mode** (`--diff-only`): Show only significant response differences
- **Quiet Mode** (`-q`): Suppress banner for scripting and automation
- **Auto-Verify** (`--verify`): Automatically re-test high-confidence findings for confirmation
- **Exit Code**: Returns exit code 1 when Critical/High findings detected (CI/CD friendly)

> **Example**: `hhunter -l urls.txt --full --report report.html --sarif results.sarif -o findings.json -q`

</details>

---

## Installation

### Go Install (Recommended)
```bash
# Install HHunter
go install -v github.com/cc1a2b/HHunter@latest

# Verify installation
hhunter --help
```

### Build from Source
```bash
git clone https://github.com/cc1a2b/HHunter.git
cd HHunter
go build -o hhunter .
```

### Platform-Specific Builds
```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o hhunter-linux .

# Windows
GOOS=windows GOARCH=amd64 go build -o hhunter.exe .

# macOS
GOOS=darwin GOARCH=amd64 go build -o hhunter-darwin .
```

### System Requirements
- **Go 1.23+** (for building from source)
- **Linux, macOS, or Windows** (64-bit architecture)
- **Network connectivity** for remote testing
- **VPS** (optional, for OOB callback server)

---

## Quick Start

### Basic Testing
```bash
# Quick auth bypass test
hhunter -u https://api.target.com/admin --auth

# Test proxy trust + CORS
hhunter -u https://api.target.com/internal --proxy --cors

# Full scan — all 22 categories
hhunter -u https://target.com/api --full
```

### Complete Security Assessment
```bash
# Full scan with HTML report
hhunter -u https://target.com/api --full --report report.html -o findings.json

# Full scan with blind vulnerability detection
hhunter -u https://target.com/api --full --oob --oob-url http://your-vps:8888

# Multi-target scan from file
hhunter -l urls.txt --full --report report.html

# Pipeline mode from other tools
cat urls.txt | hhunter --auth --proxy --injection --diff-only
```

---

## Usage Examples

```bash
# Authentication bypass testing
hhunter -u https://api.target.com/admin --auth --jwt

# SSRF hunting with cloud metadata focus
hhunter -u https://target.com --ssrf --cloud

# Injection testing (SSTI, Log4Shell, SQLi, XSS)
hhunter -u https://target.com --injection

# CORS misconfiguration detection
hhunter -u https://api.target.com/data --cors

# Cache poisoning assessment
hhunter -u https://target.com --cache --diff-only

# Full offensive scan with OOB detection
hhunter -u https://target.com/api --full --oob --oob-url http://vps:8888 -o results.json

# POST endpoint with body data
hhunter -u https://api.target.com/login -m POST -d '{"user":"admin"}' --auth --injection

# Import raw request from Burp
hhunter --raw request.txt --auth --proxy --verify

# Stealth scan through Burp Suite with WAF evasion
hhunter -u https://target.com --full --stealth --waf-evasion --proxy-url http://127.0.0.1:8080 -w 5

# Filter out noise — only 200 and 302 responses
hhunter -u https://target.com --full -ms 200,302

# Multi-target with SARIF output for CI/CD
hhunter -l urls.txt --full --sarif results.sarif -q

# Privilege escalation hunting
hhunter -u https://api.target.com --auth --priv-check --diff-only

# Custom authenticated testing
hhunter -u https://api.target.com/admin --auth -H "Authorization: Bearer eyJ..." -b "session=abc123"
```

---

## Command Reference

Get the complete help anytime with `hhunter --help`

```
Usage:
  hhunter -u <URL> [options]
  hhunter -l <file> [options]
  cat urls.txt | hhunter [options]

Target:
  -u, --url URL                 Target URL
  -l, --list FILE               File containing URLs (one per line)
  -m, --method METHOD           HTTP method (default: GET)
  -d, --data DATA               Request body data
  -ct CONTENT-TYPE              Content-Type for request body
  --raw FILE                    Raw HTTP request file (Burp format)
  stdin                         Pipe URLs from other tools

Core Attack Categories:
  --auth                        Authentication & authorization bypass
  --proxy                       Proxy trust abuse (X-Forwarded-For, etc)
  --cors                        CORS misconfigurations
  --cache                       Cache poisoning & deception
  --override                    HTTP method & URL override
  --cloud                       Cloud/CDN/K8s header injection
  --debug                       Debug mode & feature flag exposure

Advanced Attack Categories:
  --smuggling                   HTTP request smuggling (CL-TE, TE-CL)
  --injection                   Header injection (XSS, SSTI, Log4Shell, SQLi)
  --ssrf                        SSRF via headers (metadata, internal services)
  --hopbyhop                    Hop-by-hop header stripping attacks
  --ratelimit                   Rate limit bypass techniques
  --security                    Security header manipulation (CSP, HSTS)
  --websocket                   WebSocket/gRPC/GraphQL probes
  --jwt                         JWT attacks (alg:none, confusion, injection)
  --crlf                        CRLF injection / HTTP response splitting
  --cookie                      Cookie manipulation (fixation, tossing, overflow)
  --content-type                Content-Type abuse (MIME confusion, WAF bypass)
  --redirect                    Open redirect via header manipulation
  --protocol                    Protocol upgrade (h2c smuggling, HTTP/2)
  --encoding                    Encoding/charset attacks (WAF bypass, Range)
  --gateway                     API gateway/routing bypass (Kong, Envoy, etc)

Scan Control:
  --full                        Run ALL categories + audit + recon + verify + chain
  --audit                       Passive security audit (WAF, tech, headers)
  --recon                       Reconnaissance (reflection, methods, host injection)
  --verify                      Auto-verify high-confidence findings
  --chain                       Chain multiple header mutations for combo attacks
  --diff-only                   Only show significant differences
  --priv-check                  Privilege escalation detection
  --waf-evasion                 WAF bypass techniques (header case randomization)
  --stealth                     Stealth mode (slower, more evasive)

OOB (Out-of-Band) Detection:
  --oob                         Enable OOB callback server for blind vulns
  --oob-addr ADDR               OOB listen address (default: 0.0.0.0:8888)
  --oob-url URL                 External OOB URL (e.g., http://your-vps:8888)
  --oob-wait SEC                Wait time for OOB callbacks (default: 10)

HTTP Configuration:
  -w, --workers INT             Concurrent workers (default: 30)
  -r, --rate MS                 Rate limit delay in milliseconds
  -t, --timeout SEC             Request timeout in seconds (default: 30)
  -H, --header "Key: Value"     Custom header (repeatable)
  -b, --cookies "key=val; ..."  Cookie string
  --proxy-url URL               HTTP proxy (e.g., http://127.0.0.1:8080)
  -fr, --follow-redirect        Follow HTTP redirects

Matchers/Filters:
  -ms, --match-status CODES     Only process these status codes (e.g., 200,302)
  -fs, --filter-status CODES    Exclude these status codes (e.g., 404,500)
  --match-size BYTES            Only process responses of this size
  --filter-size BYTES           Exclude responses of this size

Output:
  -o, --output FILE.json        Output results to JSON file
  --report FILE.html            Generate HTML report
  --sarif FILE.sarif            Generate SARIF report (CI/CD)
  -q, --quiet                   Suppress banner
  --update, --up                Update to latest version
  -h, --help                    Show this help
```

---

## Advanced Usage

### Professional Penetration Testing
```bash
# Complete header security assessment with reports
hhunter -u https://target.com/api --full --report audit.html -o findings.json

# OOB blind vulnerability hunting on VPS
hhunter -u https://target.com --full --oob --oob-url http://your-vps:8888 --oob-wait 30 -o oob_findings.json

# Stealth reconnaissance with WAF evasion
hhunter -u https://target.com --full --waf-evasion --stealth -r 1000 -w 5 -q

# Burp Suite integration workflow
hhunter --raw burp_request.txt --auth --proxy --injection --oob --proxy-url http://127.0.0.1:8080

# POST endpoint body testing
hhunter -u https://api.target.com/login -m POST -d '{"username":"admin","password":"test"}' -ct application/json --auth --injection
```

### Bug Bounty Hunting
```bash
# Quick recon + auth bypass on API endpoints
cat api_endpoints.txt | hhunter --auth --proxy --cors --jwt --diff-only -o bounty.json

# SSRF hunting with OOB on cloud targets
hhunter -l cloud_targets.txt --ssrf --cloud --oob --oob-url http://vps:8888

# Full scan on high-value target with HTML report
hhunter -u https://api.target.com --full --report target_report.html --verify

# Injection hunting with noise filtering
hhunter -u https://target.com --injection --ssrf -fs 403,429,500 --diff-only
```

### Enterprise & CI/CD Integration
```bash
# CI/CD pipeline — fail on Critical/High findings
hhunter -u https://staging.company.com/api --full -q --sarif results.sarif -o findings.json
# Exit code 1 if Critical/High findings detected

# Automated multi-target scanning
hhunter -l production_endpoints.txt --auth --proxy --cors --cache -q -o weekly_scan.json

# GitHub Code Scanning integration
hhunter -u https://api.company.com --full --sarif results.sarif -q
# Upload results.sarif to GitHub Security tab
```

---

## Detection Categories

### Authentication Bypass (173 mutations)
- JWT none/None/NONE algorithm bypass, empty signature, weak secret signing
- JWT kid directory traversal (/dev/null, /etc/passwd), jku/x5u header poisoning
- Bearer token manipulation (null, undefined, admin, boolean, array, object)
- Basic auth default credentials (admin:admin, root:root, test:test)
- Role injection (X-Role, X-Admin, X-Privilege, X-Scope, X-ACL)
- Cloud identity spoofing (AWS ALB OIDC, GCP IAP, Azure AD principal)
- Service mesh auth bypass (Envoy, Istio attributes)
- IDOR via user/account/tenant/org ID headers
- Cookie-based auth bypass and CSRF token bypass

### SSRF via Headers (198 mutations)
- AWS IMDSv1/v2 bypass, ECS task metadata, Lambda runtime API
- Azure managed identity OAuth2 tokens (management, vault, storage, graph)
- GCP metadata with Metadata-Flavor header, service account tokens
- Kubernetes API server, secrets enumeration, etcd, kubelet
- Docker API (container/image listing)
- 50+ internal service ports (Redis, MongoDB, Elasticsearch, Consul, Vault, Prometheus, etc.)
- 20+ IP bypass techniques (octal, hex, decimal, IPv6 mapped, URL authority confusion)
- DNS rebinding (nip.io, sslip.io, lvh.me, vcap.me, traefik.me)
- URL scheme attacks (gopher, file, dict)
- Webhook/callback SSRF headers (X-Callback-URL, X-Webhook-URL, Destination)

### Injection Engine (148 mutations)
- SSTI per template engine: Jinja2, Twig, Thymeleaf, Freemarker, Velocity, Pebble, Groovy, Blade, Handlebars
- Log4Shell: LDAP/LDAPS/DNS/RMI/IIOP/CORBA + 20+ WAF bypass obfuscations + env variable exfiltration
- Blind SQLi time-based: MySQL (SLEEP, BENCHMARK), PostgreSQL (pg_sleep), MSSQL (WAITFOR), Oracle (DBMS_PIPE), SQLite
- Error-based SQLi: EXTRACTVALUE, double query, CONVERT
- Command injection: semicolon, pipe, backtick, subshell, IFS bypass, DNS exfil
- XSS: script, svg, img, details, math tag mutation, dynamic import
- NoSQL injection ($gt, $ne, $regex, $where)
- LDAP injection, OGNL RCE, Java EL, prototype pollution, GraphQL introspection

### CORS Misconfigurations (43 mutations)
- Arbitrary origin reflection with and without credentials
- Null origin exploitation via sandboxed iframe
- Subdomain bypass patterns (victim.com.evil.com, evil.victim.com)
- URL encoding bypass (%40, %23, %60, %09, %0d, %0a)
- Protocol scheme bypass (data://, javascript://, vbscript://)
- Method and header expansion detection

### Cache Poisoning (52 mutations)
- Host header injection and X-Forwarded-Host manipulation
- Cache key poisoning via unkeyed headers
- CDN-specific bypass (Cloudflare, Fastly, Akamai, Varnish)
- Cache deception attacks

### + 16 More Categories
Method override, cloud/CDN, debug exposure, HTTP smuggling, hop-by-hop, rate limit bypass, security headers, WebSocket, JWT, CRLF, cookie, content-type, redirect, protocol, encoding, API gateway — all with dedicated mutation sets.

---

## Contributing

We welcome contributions! Here's how you can help:

- **Report bugs** via [GitHub Issues](https://github.com/cc1a2b/HHunter/issues)
- **Suggest features** or new attack categories
- **Add mutations** for emerging attack vectors
- **Submit pull requests** with enhancements

### Development Setup
```bash
git clone https://github.com/cc1a2b/HHunter.git
cd HHunter
go mod tidy
go build -o hhunter .
```

### Project Structure
```
HHunter/
├── main.go                 # CLI entry point, flag parsing, scan orchestration
├── engine/
│   ├── orchestrator.go     # Core scan engine, mutation testing, finding generation
│   ├── context.go          # HTTP request execution, baseline profiling
│   ├── diff.go             # Differential analysis, auth bypass, sensitive data detection
│   ├── similarity.go       # Response similarity (LCS, structural, header comparison)
│   ├── dedup.go            # Finding deduplication by root cause
│   ├── oob.go              # Out-of-band callback server
│   ├── chain.go            # Chained multi-header attack engine
│   ├── adaptive.go         # Technology-adaptive mutation prioritization
│   ├── report.go           # HTML and SARIF report generation
│   └── probes.go           # Recon probes (reflection, methods, host injection)
├── headers/                # 15 mutation files (1100+ mutations)
│   ├── auth.go             # 173 auth bypass mutations
│   ├── ssrf.go             # 198 SSRF mutations
│   ├── injection.go        # 148 injection mutations
│   ├── cors.go             # 43 CORS mutations
│   └── ...                 # cache, cloud, debug, smuggling, jwt, crlf, etc.
└── detectors/              # Response analysis detectors
```

---

## License

HHunter is released under the **MIT License**. See [LICENSE](LICENSE) for details.

```
Copyright (c) 2024-2026 Hussain Alsharman
Licensed under MIT License - free for commercial and personal use
```

---

## Support

If HHunter helps with your security research or professional work:

<div align="center">

[![Buy Me A Coffee](https://cdn.buymeacoffee.com/buttons/default-orange.png)](https://www.buymeacoffee.com/cc1a2b)

**Star this repo** | **Follow [@cc1a2b](https://twitter.com/cc1a2b)** | **Share with others**

</div>

---

<div align="center">

**HHunter — Advanced HTTP Header Vulnerability Scanner**

*Built by [cc1a2b](https://github.com/cc1a2b) for the security community*

</div>
