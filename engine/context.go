package engine

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type RequestContext struct {
	URL         string
	Method      string
	Headers     map[string]string
	Body        []byte
	ProxyURL    string
	Timeout     time.Duration
	FollowRedir bool
}

type ResponseContext struct {
	StatusCode    int
	Headers       map[string][]string
	Body          []byte
	BodyHash      string
	ContentLength int64
	TimingMS      int64
	JSONKeys      []string
	Error         error
}

type Mutation struct {
	Header   string
	Value    string
	Category string
	Impact   string
}

type Finding struct {
	Header          string            `json:"header"`
	Payload         string            `json:"payload"`
	Impact          string            `json:"impact"`
	Confidence      string            `json:"confidence"`
	ConfidenceScore float64           `json:"confidence_score"`
	Evidence        map[string]string `json:"evidence"`
	Category        string            `json:"category"`
	Severity        string            `json:"severity"`
	CVSS            float64           `json:"cvss,omitempty"`
	CWE             string            `json:"cwe,omitempty"`
	Remediation     string            `json:"remediation,omitempty"`
	References      []string          `json:"references,omitempty"`
	Request         string            `json:"request,omitempty"`
	Response        string            `json:"response,omitempty"`
	Timestamp       time.Time         `json:"timestamp"`
	Verified        bool              `json:"verified,omitempty"`
	VerifiedAt      time.Time         `json:"verified_at,omitempty"`
	ReconSource     string            `json:"recon_source,omitempty"`
}

type MissingSecurityHeader struct {
	Header      string `json:"header"`
	Severity    string `json:"severity"`
	Impact      string `json:"impact"`
	Remediation string `json:"remediation"`
	CWE         string `json:"cwe"`
}

type InfoLeak struct {
	Type     string `json:"type"`
	Header   string `json:"header"`
	Value    string `json:"value"`
	Severity string `json:"severity"`
}

type TechFingerprint struct {
	Technology string `json:"technology"`
	Version    string `json:"version"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
}

type CORSAnalysis struct {
	AllowOrigin      string `json:"allow_origin"`
	AllowCredentials bool   `json:"allow_credentials"`
	AllowMethods     string `json:"allow_methods"`
	AllowHeaders     string `json:"allow_headers"`
	ExposeHeaders    string `json:"expose_headers"`
	MaxAge           string `json:"max_age"`
	Vulnerable       bool   `json:"vulnerable"`
	Details          string `json:"details"`
}

type ReconSummary struct {
	ReflectedHeaders  []string `json:"reflected_headers,omitempty"`
	AllowedMethods    []string `json:"allowed_methods,omitempty"`
	DangerousMethods  []string `json:"dangerous_methods,omitempty"`
	TraceEnabled      bool     `json:"trace_enabled"`
	HostInjectable    []string `json:"host_injectable,omitempty"`
	VerbTamperBypasses int     `json:"verb_tamper_bypasses"`
}

type SecurityAudit struct {
	MissingHeaders   []MissingSecurityHeader `json:"missing_headers"`
	InformationLeaks []InfoLeak              `json:"information_leaks"`
	TechFingerprints []TechFingerprint       `json:"tech_fingerprints"`
	WAFDetected      string                  `json:"waf_detected"`
	ServerInfo       string                  `json:"server_info"`
	CORSAnalysis     *CORSAnalysis           `json:"cors_analysis,omitempty"`
}

func NewRequestContext(url, method string) *RequestContext {
	return &RequestContext{
		URL:         url,
		Method:      method,
		Headers:     make(map[string]string),
		Timeout:     30 * time.Second,
		FollowRedir: false,
	}
}

func (rc *RequestContext) Clone() *RequestContext {
	clone := &RequestContext{
		URL:         rc.URL,
		Method:      rc.Method,
		Headers:     make(map[string]string),
		Body:        rc.Body,
		ProxyURL:    rc.ProxyURL,
		Timeout:     rc.Timeout,
		FollowRedir: rc.FollowRedir,
	}
	for k, v := range rc.Headers {
		clone.Headers[k] = v
	}
	return clone
}

func (rc *RequestContext) AddHeader(key, value string) {
	rc.Headers[key] = value
}

// SetBody sets the request body and auto-sets Content-Type if not already set
func (rc *RequestContext) SetBody(body []byte, contentType string) {
	rc.Body = body
	if contentType != "" {
		if _, exists := rc.Headers["Content-Type"]; !exists {
			rc.Headers["Content-Type"] = contentType
		}
	}
}

func (rc *RequestContext) Execute(client *http.Client) (*ResponseContext, error) {
	start := time.Now()

	var bodyReader io.Reader
	if len(rc.Body) > 0 {
		bodyReader = bytes.NewReader(rc.Body)
	}

	req, err := http.NewRequest(rc.Method, rc.URL, bodyReader)
	if err != nil {
		return nil, err
	}

	for k, v := range rc.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		return &ResponseContext{
			Error:    err,
			TimingMS: elapsed,
		}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &ResponseContext{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			TimingMS:   elapsed,
			Error:      err,
		}, err
	}

	hash := sha256.Sum256(body)
	contentLength := int64(len(body))
	if resp.ContentLength > 0 {
		contentLength = resp.ContentLength
	}

	return &ResponseContext{
		StatusCode:    resp.StatusCode,
		Headers:       resp.Header,
		Body:          body,
		BodyHash:      fmt.Sprintf("%x", hash),
		ContentLength: contentLength,
		TimingMS:      elapsed,
	}, nil
}

func RunSecurityAudit(resp *ResponseContext) *SecurityAudit {
	audit := &SecurityAudit{}
	audit.MissingHeaders = checkMissingSecurityHeaders(resp)
	audit.InformationLeaks = detectInformationLeaks(resp)
	audit.TechFingerprints = fingerprintTechnology(resp)
	audit.WAFDetected = detectWAF(resp)
	audit.ServerInfo = extractServerInfo(resp)
	audit.CORSAnalysis = analyzeCORS(resp)
	return audit
}

func checkMissingSecurityHeaders(resp *ResponseContext) []MissingSecurityHeader {
	missing := []MissingSecurityHeader{}

	// Only report headers that represent real, exploitable security gaps
	// Excluded: X-XSS-Protection (deprecated, harmful), X-Permitted-Cross-Domain-Policies (Flash is dead),
	// COEP/COOP/CORP (niche cross-origin isolation, not a vulnerability if missing)
	securityHeaders := []struct {
		header      string
		severity    string
		impact      string
		remediation string
		cwe         string
	}{
		{"Strict-Transport-Security", "High", "No HSTS - vulnerable to SSL stripping attacks", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload", "CWE-319"},
		{"Content-Security-Policy", "Medium", "No CSP - reduced XSS mitigation", "Add Content-Security-Policy with restrictive directives", "CWE-79"},
		{"X-Content-Type-Options", "Low", "No content type sniffing protection", "Add: X-Content-Type-Options: nosniff", "CWE-16"},
		{"X-Frame-Options", "Medium", "No clickjacking protection", "Add: X-Frame-Options: DENY or SAMEORIGIN", "CWE-1021"},
		{"Referrer-Policy", "Low", "No referrer policy - may leak sensitive URLs", "Add: Referrer-Policy: strict-origin-when-cross-origin", "CWE-200"},
	}

	for _, sh := range securityHeaders {
		if _, exists := resp.Headers[sh.header]; !exists {
			headerLower := strings.ToLower(sh.header)
			found := false
			for k := range resp.Headers {
				if strings.ToLower(k) == headerLower {
					found = true
					break
				}
			}
			if !found {
				missing = append(missing, MissingSecurityHeader{
					Header:      sh.header,
					Severity:    sh.severity,
					Impact:      sh.impact,
					Remediation: sh.remediation,
					CWE:         sh.cwe,
				})
			}
		}
	}

	return missing
}

func detectInformationLeaks(resp *ResponseContext) []InfoLeak {
	leaks := []InfoLeak{}

	// Only flag headers that reveal actionable information (versions, internal paths, debug tokens)
	// Skip generic CDN/cache identifiers that provide no exploitable info
	infoHeaders := map[string]string{
		"X-Powered-By":       "Technology Disclosure",
		"X-AspNet-Version":   "ASP.NET Version Disclosure",
		"X-AspNetMvc-Version": "ASP.NET MVC Version Disclosure",
		"X-Version":          "Application Version Disclosure",
		"X-Generator":        "Generator Disclosure",
		"X-Backend-Server":   "Backend Server Disclosure",
		"X-Debug-Token":      "Debug Token Disclosure",
		"X-Debug-Token-Link": "Debug Token Link Disclosure",
	}

	for headerName, leakType := range infoHeaders {
		for k, vals := range resp.Headers {
			if strings.EqualFold(k, headerName) && len(vals) > 0 && vals[0] != "" {
				severity := "Low"
				if headerName == "X-Powered-By" || headerName == "X-AspNet-Version" {
					severity = "Medium"
				}
				if headerName == "X-Debug-Token" || headerName == "X-Debug-Token-Link" {
					severity = "High"
				}
				leaks = append(leaks, InfoLeak{
					Type:     leakType,
					Header:   k,
					Value:    vals[0],
					Severity: severity,
				})
			}
		}
	}

	// Server header — only flag if it contains a version number (e.g., "nginx/1.19.0", "Apache/2.4.41")
	// Generic names like "cloudflare", "nginx", "Apache" without version are not actionable
	for k, vals := range resp.Headers {
		if strings.EqualFold(k, "Server") && len(vals) > 0 && vals[0] != "" {
			val := vals[0]
			if containsVersionNumber(val) {
				leaks = append(leaks, InfoLeak{
					Type:     "Server Version Disclosure",
					Header:   k,
					Value:    val,
					Severity: "Medium",
				})
			}
		}
	}

	return leaks
}

// containsVersionNumber checks if a string contains a version pattern like "/1.2.3" or "1.2"
func containsVersionNumber(s string) bool {
	// Match patterns like "nginx/1.19.0", "Apache/2.4.41", "PHP/8.1.2", "Microsoft-IIS/10.0"
	versionPattern := regexp.MustCompile(`[\d]+\.[\d]+`)
	return versionPattern.MatchString(s)
}

func fingerprintTechnology(resp *ResponseContext) []TechFingerprint {
	fingerprints := []TechFingerprint{}

	for k, vals := range resp.Headers {
		if len(vals) == 0 || vals[0] == "" {
			continue
		}
		v := vals[0]
		kl := strings.ToLower(k)

		if kl == "server" {
			fp := TechFingerprint{Source: k, Confidence: "High"}
			vl := strings.ToLower(v)
			switch {
			case strings.Contains(vl, "nginx"):
				fp.Technology = "Nginx"
			case strings.Contains(vl, "apache"):
				fp.Technology = "Apache"
			case strings.Contains(vl, "iis"):
				fp.Technology = "Microsoft IIS"
			case strings.Contains(vl, "cloudflare"):
				fp.Technology = "Cloudflare"
			case strings.Contains(vl, "openresty"):
				fp.Technology = "OpenResty"
			case strings.Contains(vl, "gunicorn"):
				fp.Technology = "Gunicorn"
			case strings.Contains(vl, "uvicorn"):
				fp.Technology = "Uvicorn"
			case strings.Contains(vl, "envoy"):
				fp.Technology = "Envoy Proxy"
			case strings.Contains(vl, "caddy"):
				fp.Technology = "Caddy"
			case strings.Contains(vl, "lighttpd"):
				fp.Technology = "Lighttpd"
			case strings.Contains(vl, "litespeed"):
				fp.Technology = "LiteSpeed"
			case strings.Contains(vl, "cowboy"):
				fp.Technology = "Cowboy (Erlang)"
			case strings.Contains(vl, "kestrel"):
				fp.Technology = "Kestrel (.NET)"
			case strings.Contains(vl, "jetty"):
				fp.Technology = "Jetty (Java)"
			case strings.Contains(vl, "tomcat"):
				fp.Technology = "Apache Tomcat"
			default:
				fp.Technology = "Unknown Server"
			}
			fp.Version = v
			fingerprints = append(fingerprints, fp)
		}

		if kl == "x-powered-by" {
			fp := TechFingerprint{Source: k, Version: v, Confidence: "High"}
			vl := strings.ToLower(v)
			switch {
			case strings.Contains(vl, "php"):
				fp.Technology = "PHP"
			case strings.Contains(vl, "asp.net"):
				fp.Technology = "ASP.NET"
			case strings.Contains(vl, "express"):
				fp.Technology = "Express.js"
			case strings.Contains(vl, "next.js"):
				fp.Technology = "Next.js"
			case strings.Contains(vl, "flask"):
				fp.Technology = "Flask"
			case strings.Contains(vl, "django"):
				fp.Technology = "Django"
			case strings.Contains(vl, "rails"):
				fp.Technology = "Ruby on Rails"
			case strings.Contains(vl, "spring"):
				fp.Technology = "Spring Framework"
			case strings.Contains(vl, "laravel"):
				fp.Technology = "Laravel"
			default:
				fp.Technology = v
			}
			fingerprints = append(fingerprints, fp)
		}

		if kl == "x-aspnet-version" || kl == "x-aspnetmvc-version" {
			fingerprints = append(fingerprints, TechFingerprint{
				Technology: "ASP.NET", Version: v, Source: k, Confidence: "High",
			})
		}
	}

	// Detect cloud providers from header prefixes — but skip if already identified via Server header
	techSet := make(map[string]bool)
	for _, fp := range fingerprints {
		techSet[strings.ToLower(fp.Technology)] = true
	}

	for k := range resp.Headers {
		kl := strings.ToLower(k)
		if strings.HasPrefix(kl, "cf-") && !techSet["cloudflare"] {
			fingerprints = append(fingerprints, TechFingerprint{
				Technology: "Cloudflare", Version: "", Source: k, Confidence: "High",
			})
			techSet["cloudflare"] = true
			break
		}
	}
	for k := range resp.Headers {
		kl := strings.ToLower(k)
		if strings.HasPrefix(kl, "x-amz-") && !techSet["aws"] {
			fingerprints = append(fingerprints, TechFingerprint{
				Technology: "AWS", Version: "", Source: k, Confidence: "High",
			})
			techSet["aws"] = true
			break
		}
	}
	for k := range resp.Headers {
		kl := strings.ToLower(k)
		if strings.HasPrefix(kl, "x-azure-") && !techSet["azure"] {
			fingerprints = append(fingerprints, TechFingerprint{
				Technology: "Azure", Version: "", Source: k, Confidence: "High",
			})
			break
		}
	}

	return fingerprints
}

func detectWAF(resp *ResponseContext) string {
	wafSignatures := map[string]map[string]string{
		"Cloudflare": {"Server": "cloudflare", "CF-RAY": ""},
		"AWS WAF":    {"X-Amzn-RequestId": "", "X-Amz-Cf-Id": ""},
		"Akamai":     {"X-Akamai-Transformed": "", "Server": "akamai"},
		"Imperva":    {"X-CDN": "imperva", "X-Iinfo": ""},
		"F5 BIG-IP":  {"Server": "bigip", "X-WA-Info": ""},
		"Barracuda":  {"Server": "barracuda"},
		"Sucuri":     {"Server": "sucuri", "X-Sucuri-ID": ""},
		"ModSecurity": {"Server": "modsecurity"},
		"Fastly":     {"X-Fastly-Request-ID": "", "Fastly-Debug-Digest": ""},
		"Varnish":    {"X-Varnish": "", "Via": "varnish"},
	}

	for wafName, signatures := range wafSignatures {
		for sigHeader, sigValue := range signatures {
			for k, vals := range resp.Headers {
				if strings.EqualFold(k, sigHeader) && len(vals) > 0 {
					if sigValue == "" || strings.Contains(strings.ToLower(vals[0]), strings.ToLower(sigValue)) {
						return wafName
					}
				}
			}
		}
	}

	body := strings.ToLower(string(resp.Body))
	wafBodySignatures := map[string][]string{
		"Cloudflare":  {"cloudflare", "ray id:", "cf-browser-verification"},
		"AWS WAF":     {"<awswafaction>", "request blocked"},
		"ModSecurity": {"modsecurity", "mod_security", "noyb"},
		"Imperva":     {"incapsula", "_incap_"},
		"Sucuri":      {"sucuri", "access denied - sucuri"},
		"Akamai":      {"akamai", "reference #"},
		"F5 BIG-IP":   {"the requested url was rejected", "support id:"},
		"Barracuda":   {"barracuda", "barra_counter_session"},
		"FortiWeb":    {"fortiweb", ".fwb_token"},
		"DenyAll":     {"conditionblocked", "denyall"},
	}

	for wafName, patterns := range wafBodySignatures {
		for _, pattern := range patterns {
			if strings.Contains(body, pattern) {
				return wafName
			}
		}
	}

	if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 || resp.StatusCode == 503 {
		for k := range resp.Headers {
			kl := strings.ToLower(k)
			if strings.Contains(kl, "waf") || strings.Contains(kl, "firewall") || strings.Contains(kl, "shield") {
				return "Unknown WAF (header: " + k + ")"
			}
		}
	}

	return ""
}

func extractServerInfo(resp *ResponseContext) string {
	for k, vals := range resp.Headers {
		if strings.EqualFold(k, "Server") && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

// ParseRawRequest parses a raw HTTP request (e.g., from Burp Suite copy-paste)
// and returns a RequestContext. The raw format is:
//
//	GET /path HTTP/1.1
//	Host: example.com
//	Header: value
//
//	optional body
func ParseRawRequest(raw string, useTLS bool) (*RequestContext, error) {
	reader := bufio.NewReader(strings.NewReader(raw))

	// Parse request line
	requestLine, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read request line: %w", err)
	}
	requestLine = strings.TrimSpace(requestLine)

	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line: %s", requestLine)
	}

	method := parts[0]
	path := parts[1]

	rc := &RequestContext{
		Method:  method,
		Headers: make(map[string]string),
		Timeout: 30 * time.Second,
	}

	// Parse headers
	var host string
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")

		if line == "" {
			break
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}

		key := strings.TrimSpace(line[:colonIdx])
		value := strings.TrimSpace(line[colonIdx+1:])

		if strings.EqualFold(key, "Host") {
			host = value
		}
		rc.Headers[key] = value

		if err != nil {
			break
		}
	}

	// Read remaining as body
	var bodyBuilder strings.Builder
	for {
		line, err := reader.ReadString('\n')
		bodyBuilder.WriteString(line)
		if err != nil {
			break
		}
	}
	body := strings.TrimSpace(bodyBuilder.String())
	if body != "" {
		rc.Body = []byte(body)
	}

	// Build URL from host and path
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	if host == "" {
		return nil, fmt.Errorf("no Host header found in raw request")
	}
	rc.URL = fmt.Sprintf("%s://%s%s", scheme, host, path)

	return rc, nil
}

func analyzeCORS(resp *ResponseContext) *CORSAnalysis {
	analysis := &CORSAnalysis{}
	hasCORS := false

	for k, vals := range resp.Headers {
		kl := strings.ToLower(k)
		if len(vals) == 0 {
			continue
		}
		switch kl {
		case "access-control-allow-origin":
			analysis.AllowOrigin = vals[0]
			hasCORS = true
		case "access-control-allow-credentials":
			analysis.AllowCredentials = strings.EqualFold(vals[0], "true")
		case "access-control-allow-methods":
			analysis.AllowMethods = vals[0]
		case "access-control-allow-headers":
			analysis.AllowHeaders = vals[0]
		case "access-control-expose-headers":
			analysis.ExposeHeaders = vals[0]
		case "access-control-max-age":
			analysis.MaxAge = vals[0]
		}
	}

	if !hasCORS {
		return nil
	}

	if analysis.AllowOrigin == "*" && analysis.AllowCredentials {
		analysis.Vulnerable = true
		analysis.Details = "CRITICAL: Wildcard origin with credentials allowed"
	} else if analysis.AllowOrigin == "*" {
		analysis.Vulnerable = true
		analysis.Details = "Wildcard origin - any site can make cross-origin requests"
	} else if analysis.AllowOrigin == "null" {
		analysis.Vulnerable = true
		analysis.Details = "Null origin allowed - exploitable via sandboxed iframes"
	}

	return analysis
}
