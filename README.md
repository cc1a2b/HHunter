# HHunter - Advanced Header Testing Engine

HHunter is a powerful Go-based security testing tool designed to detect logic flaws, trust abuse, WAF bypass, authentication confusion, and other vulnerabilities through intelligent HTTP header mutation and analysis.

## Features

- **Intelligent Header Mutation**: Tests multiple categories of header-based attacks
- **Differential Analysis**: Compares baseline vs mutated responses to detect anomalies
- **Privilege Detection**: Identifies privilege escalation and authentication bypass
- **WAF Evasion**: Built-in techniques to bypass Web Application Firewalls
- **Concurrent Scanning**: Fast, multi-threaded execution with rate limiting
- **JSON Output**: Export findings in machine-readable format

## Header Categories

### 1. Authentication & Identity (`--auth`)
- Authorization bypass with null/undefined tokens
- API key manipulation
- Role-based access control bypass
- CSRF token bypass

### 2. Proxy & Trust Headers (`--proxy`)
- X-Forwarded-For IP spoofing
- Internal network access via trusted headers
- Cloud metadata access (169.254.169.254)
- Protocol confusion attacks

### 3. CORS Testing (`--cors`)
- Origin validation bypass
- Null origin exploitation
- Subdomain takeover detection

### 4. Cache Poisoning (`--cache`)
- Host header injection
- Cache deception attacks
- Protocol downgrade via cache

### 5. Method Override (`--override`)
- HTTP method override (PUT, DELETE, PATCH)
- URL rewrite attacks
- Path traversal via override headers

### 6. Cloud/CDN Headers (`--cloud`)
- Cloudflare bypass (CF-Connecting-IP)
- AWS, Azure, GCP header injection
- CDN trust chain abuse

### 7. Debug & Legacy (`--debug`)
- Debug mode activation
- Stack trace exposure
- Feature flag manipulation

## Installation

```bash
git clone https://github.com/yourusername/hhunter
cd hhunter
go build -o hhunter
```

## Usage

### Basic Scan

```bash
hhunter scan -u https://api.target.com/profile
```

### Target Specific Categories

```bash
# Test authentication headers only
hhunter scan -u https://api.target.com/admin --auth

# Test proxy and cache headers
hhunter scan -u https://api.target.com/api --proxy --cache

# All categories
hhunter scan -u https://target.com --auth --proxy --cors --cache --override --cloud --debug
```

### Advanced Options

```bash
# With WAF evasion and stealth mode
hhunter scan -u https://target.com/api \
  --auth \
  --proxy \
  --waf-evasion \
  --stealth \
  -o results.json

# Through proxy with custom workers
hhunter scan -u https://target.com \
  --auth \
  --proxy-url http://127.0.0.1:8080 \
  --workers 50 \
  --rate 100

# Diff-only mode (show only significant findings)
hhunter scan -u https://api.target.com \
  --auth \
  --proxy \
  --diff-only

# With custom headers
hhunter scan -u https://api.target.com \
  --auth \
  -H "Cookie: session=abc123" \
  -H "User-Agent: Custom"
```

## Command-Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-u, --url` | Target URL (required) | - |
| `-m, --method` | HTTP method | GET |
| `--auth` | Test authentication headers | false |
| `--proxy` | Test proxy trust headers | false |
| `--cors` | Test CORS headers | false |
| `--cache` | Test cache poisoning | false |
| `--override` | Test method override | false |
| `--cloud` | Test cloud/CDN headers | false |
| `--debug` | Test debug headers | false |
| `--chain` | Chain multiple mutations | false |
| `--diff-only` | Only show significant diffs | false |
| `--priv-check` | Check privilege escalation | false |
| `--waf-evasion` | Enable WAF bypass techniques | false |
| `--stealth` | Stealth mode (slower) | false |
| `--proxy-url` | HTTP proxy URL | - |
| `-o, --output` | Output file (JSON) | - |
| `-w, --workers` | Concurrent workers | 30 |
| `-r, --rate` | Rate limit (ms) | 0 |
| `-t, --timeout` | Request timeout (seconds) | 30 |
| `-H, --header` | Custom header | - |

## Output Format

HHunter outputs findings in JSON format when using the `-o` flag:

```json
[
  {
    "header": "X-Forwarded-For",
    "payload": "127.0.0.1",
    "impact": "IP Whitelist Bypass",
    "confidence": "High",
    "category": "Proxy",
    "severity": "Critical",
    "evidence": {
      "status_change": "401 → 200",
      "auth_bypass": "true"
    },
    "timestamp": "2024-01-15T10:30:00Z"
  }
]
```

## Detection Engine

HHunter uses intelligent differential analysis to detect vulnerabilities:

1. **Baseline Request**: Establishes normal behavior
2. **Mutation Testing**: Injects various header payloads
3. **Differential Analysis**: Compares responses
4. **Evidence Collection**: Documents anomalies
5. **Severity Scoring**: Prioritizes findings

### Detection Criteria

- Status code transitions (401→200, 403→200)
- Response body changes (hash comparison)
- New JSON keys appearing
- Privilege escalation indicators
- Timing anomalies
- Response size changes

## WAF Evasion Techniques

When `--waf-evasion` is enabled:

- Header case randomization (X-fOrWaRdEd-FoR)
- Duplicate headers
- Whitespace smuggling
- HTTP version manipulation

## Use Cases

### 1. Penetration Testing
```bash
hhunter scan -u https://target.com/api --auth --proxy --waf-evasion -o findings.json
```

### 2. Bug Bounty Hunting
```bash
hhunter scan -u https://api.example.com --auth --cors --cache --diff-only
```

### 3. Security Assessment
```bash
hhunter scan -u https://internal.company.com --proxy --cloud --stealth
```

### 4. WAF Testing
```bash
hhunter scan -u https://protected.site.com --waf-evasion --proxy-url http://localhost:8080
```

## Best Practices

1. **Always get authorization** before testing production systems
2. **Use rate limiting** (`--rate`) to avoid overwhelming targets
3. **Enable stealth mode** for sensitive engagements
4. **Route through Burp/ZAP** using `--proxy-url` for manual verification
5. **Review findings manually** - automated tools can have false positives

## Examples

### Example 1: Finding Auth Bypass
```bash
$ hhunter scan -u https://api.example.com/profile --auth

[*] Starting HHunter scan...
[*] Establishing baseline...
[+] Baseline: 401 (size: 45, time: 123ms)
[*] Generated 30 mutations
[12/30] X-Forwarded-For: 127.0.0.1 -> 401->200 AUTH_BYPASS

[!] Found 1 potential vulnerabilities:
─────────────────────────────────────────
[!] Finding #1
  Header: X-Forwarded-For
  Payload: 127.0.0.1
  Impact: IP Whitelist Bypass
  Severity: Critical
  Confidence: High
  Evidence:
    - status_change: 401 → 200
    - auth_bypass: true
```

### Example 2: Cache Poisoning
```bash
$ hhunter scan -u https://example.com/api --cache --diff-only -o cache.json

[*] Starting HHunter scan...
[+] Baseline: 200 (size: 1234, time: 89ms)
[*] Generated 16 mutations
[5/16] X-Forwarded-Host: evil.com -> NEW_KEYS:['location']

[+] Results saved to cache.json
```

## Architecture

```
hhunter/
├── engine/          # Core scanning engine
│   ├── orchestrator.go  # Main scan coordinator
│   ├── context.go       # Request/response handling
│   └── diff.go          # Differential analysis
├── headers/         # Attack payloads by category
│   ├── auth.go
│   ├── proxy.go
│   ├── cors.go
│   ├── cache.go
│   ├── override.go
│   ├── cloud.go
│   └── debug.go
├── detectors/       # Intelligence layer
│   ├── status.go
│   ├── body.go
│   ├── timing.go
│   └── privilege.go
└── payloads/        # JSON payload definitions
```

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

MIT License - see LICENSE file

## Disclaimer

This tool is for authorized security testing only. Users are responsible for obtaining proper authorization before testing any systems they do not own.

## Credits

Created for offensive security professionals, penetration testers, and bug bounty hunters.
