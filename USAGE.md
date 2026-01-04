# HHunter Usage Guide

## Quick Start

```bash
# Build the project
cd hhunter
go build -o hhunter

# Or use Make
make build

# Run a basic scan
./hhunter scan -u https://api.target.com
```

## Common Scanning Scenarios

### 1. Authentication Bypass Testing

```bash
# Test for auth header vulnerabilities
./hhunter scan -u https://api.target.com/admin \
  --auth \
  --diff-only

# Common findings:
# - Bearer null/undefined bypass
# - X-User-Id manipulation
# - Role escalation via X-Role header
```

### 2. Proxy Trust Abuse

```bash
# Test proxy headers for IP-based access control
./hhunter scan -u https://api.target.com/internal \
  --proxy \
  --waf-evasion

# Tests for:
# - X-Forwarded-For: 127.0.0.1
# - X-Real-IP spoofing
# - Cloud metadata access (169.254.169.254)
```

### 3. CORS Misconfiguration

```bash
# Test CORS policies
./hhunter scan -u https://api.target.com/data \
  --cors

# Checks:
# - Reflected origins
# - Null origin acceptance
# - Credentials + wildcard
```

### 4. Cache Poisoning

```bash
# Test for cache poisoning vectors
./hhunter scan -u https://target.com/api \
  --cache \
  --diff-only \
  -o cache_findings.json

# Detects:
# - Host header injection
# - X-Forwarded-Host poisoning
# - Cache key manipulation
```

### 5. Method Override Exploits

```bash
# Test HTTP method override
./hhunter scan -u https://api.target.com/resource/123 \
  --override

# Tries:
# - X-HTTP-Method-Override: DELETE
# - X-Method-Override: PUT
# - URL rewrite attacks
```

### 6. Cloud Infrastructure Detection

```bash
# Identify cloud provider and test CDN headers
./hhunter scan -u https://target.com \
  --cloud

# Tests:
# - Cloudflare (CF-Connecting-IP)
# - AWS headers
# - Azure/GCP detection
```

### 7. Debug Mode Discovery

```bash
# Find debug/development features
./hhunter scan -u https://target.com/api \
  --debug

# Looks for:
# - X-Debug: true responses
# - Stack trace leakage
# - Verbose error messages
```

## Advanced Usage

### Complete Scan (All Categories)

```bash
./hhunter scan -u https://target.com/api \
  --auth \
  --proxy \
  --cors \
  --cache \
  --override \
  --cloud \
  --debug \
  --diff-only \
  -o complete_scan.json
```

### Stealth Scan Through Proxy

```bash
./hhunter scan -u https://target.com \
  --auth \
  --proxy \
  --stealth \
  --waf-evasion \
  --proxy-url http://127.0.0.1:8080 \
  --rate 500 \
  --workers 10
```

### High-Speed Scan

```bash
./hhunter scan -u https://target.com/api \
  --auth \
  --proxy \
  --workers 100 \
  --diff-only
```

### Custom Headers

```bash
./hhunter scan -u https://api.target.com/profile \
  --auth \
  -H "Cookie: session=abc123" \
  -H "X-API-Version: 2.0"
```

## Understanding Output

### Terminal Output

```
[*] Starting HHunter scan...
[*] Establishing baseline...
[+] Baseline: 401 (size: 45, time: 123ms)
[*] Generated 63 mutations
[12/63] X-Forwarded-For: 127.0.0.1 -> 401->200 AUTH_BYPASS
[23/63] X-Role: admin -> PRIV_ELEVATE NEW_KEYS:['permissions']
[45/63] Origin: null -> 403->200

[+] Scan complete. Found 3 findings.

[!] Found 3 potential vulnerabilities:
─────────────────────────────────────────
[!] Finding #1
  Header: X-Forwarded-For
  Payload: 127.0.0.1
  Impact: IP Whitelist Bypass
  Category: Proxy
  Severity: Critical
  Confidence: High
  Evidence:
    - status_change: 401 → 200
    - auth_bypass: true
```

### JSON Output Structure

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

## Evidence Types

| Evidence Key | Description |
|-------------|-------------|
| `status_change` | HTTP status code transition |
| `auth_bypass` | Authentication bypass detected |
| `privilege_elevation` | Privilege escalation detected |
| `new_json_keys` | New JSON fields in response |
| `body_hash_changed` | Response body modified |
| `headers_added` | New headers in response |
| `role_change` | User role changed |
| `admin_content_exposed` | Admin panel/features exposed |

## Severity Levels

- **Critical**: Authentication bypass, privilege escalation to admin
- **High**: Access control bypass, significant privilege changes
- **Medium**: Information disclosure, minor security issues
- **Low**: Configuration issues

## Performance Tuning

### Fast Scan (Less Accurate)
```bash
./hhunter scan -u https://target.com \
  --workers 100 \
  --diff-only
```

### Balanced Scan
```bash
./hhunter scan -u https://target.com \
  --workers 30 \
  --rate 100
```

### Stealth Scan (Most Accurate)
```bash
./hhunter scan -u https://target.com \
  --stealth \
  --workers 5 \
  --rate 1000
```

## Integration with Other Tools

### With Burp Suite

```bash
# Route through Burp for manual verification
./hhunter scan -u https://target.com \
  --auth \
  --proxy-url http://127.0.0.1:8080
```

### With OWASP ZAP

```bash
./hhunter scan -u https://target.com \
  --proxy-url http://127.0.0.1:8081 \
  --auth \
  --proxy
```

### Pipeline Integration

```bash
# Save results and check exit code
./hhunter scan -u $TARGET_URL --auth --proxy -o findings.json
if [ -s findings.json ]; then
  echo "Vulnerabilities found!"
  cat findings.json | jq '.[] | select(.severity == "Critical")'
fi
```

## Troubleshooting

### No Findings Detected
- Try removing `--diff-only` to see all mutations
- Increase timeout with `-t 60`
- Check if target is actually vulnerable
- Verify baseline request succeeds

### Too Many False Positives
- Use `--diff-only` flag
- Increase confidence threshold manually
- Review evidence carefully

### Rate Limited / Blocked
- Decrease workers: `--workers 5`
- Increase rate limit: `--rate 1000`
- Enable stealth: `--stealth`
- Use WAF evasion: `--waf-evasion`

### SSL Errors
- HHunter automatically skips SSL verification
- Check proxy settings if using `--proxy-url`

## Best Practices

1. **Start with diff-only**: `--diff-only` reduces noise
2. **Test incrementally**: Start with one category, then expand
3. **Save results**: Always use `-o output.json`
4. **Manual verification**: Review findings in Burp/ZAP
5. **Rate limiting**: Use `--rate` for production systems
6. **Authorization**: Get written permission before testing

## Example Workflows

### Bug Bounty Workflow

```bash
# 1. Quick scan for low-hanging fruit
./hhunter scan -u https://api.target.com \
  --auth --proxy --diff-only -o quick.json

# 2. Deep dive on interesting endpoints
./hhunter scan -u https://api.target.com/admin \
  --auth --proxy --cors --cache --override \
  -o deep.json

# 3. Stealth scan for WAF bypass
./hhunter scan -u https://api.target.com/protected \
  --waf-evasion --stealth --rate 500 \
  --proxy-url http://127.0.0.1:8080 \
  -o waf_bypass.json
```

### Penetration Testing Workflow

```bash
# 1. Initial reconnaissance
./hhunter scan -u https://target.com --cloud -o recon.json

# 2. Auth testing
./hhunter scan -u https://target.com/api --auth --priv-check -o auth.json

# 3. Trust boundary testing
./hhunter scan -u https://target.com/internal --proxy --cache -o trust.json

# 4. Comprehensive scan
./hhunter scan -u https://target.com \
  --auth --proxy --cors --cache --override --cloud --debug \
  --diff-only -o full_scan.json
```

### CI/CD Integration

```bash
#!/bin/bash
# security_scan.sh

TARGET="https://staging.example.com"
OUTPUT="hhunter_results.json"

./hhunter scan -u $TARGET \
  --auth --proxy --cors \
  --diff-only \
  -o $OUTPUT

# Check for critical findings
CRITICAL=$(cat $OUTPUT | jq '[.[] | select(.severity == "Critical")] | length')

if [ "$CRITICAL" -gt 0 ]; then
  echo "❌ Critical vulnerabilities found: $CRITICAL"
  exit 1
else
  echo "✅ No critical vulnerabilities"
  exit 0
fi
```

## Tips & Tricks

1. **Combine with subfinder/amass** for target discovery
2. **Use jq** to filter JSON results by severity
3. **Create custom wordlists** by modifying payload files
4. **Chain with other tools** using `--proxy-url`
5. **Test localhost** services with proxy headers
6. **Look for timing differences** in responses
7. **Check cloud metadata** endpoints (169.254.169.254)

## Additional Resources

- Check `payloads/*.json` for mutation patterns
- Modify `headers/*.go` to add custom tests
- See `examples/basic_scan.go` for programmatic usage
- Review `engine/diff.go` for detection logic
