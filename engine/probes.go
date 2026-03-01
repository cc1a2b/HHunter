package engine

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ReconResult holds all reconnaissance findings from the pre-scan phase
type ReconResult struct {
	Reflections    []ReflectionHit
	VerbTamper     *VerbTamperResult
	HostInjections []HostInjectionResult
	TotalRequests  int
}

// ReflectionHit records where a canary was reflected via a specific header
type ReflectionHit struct {
	Header   string
	Canary   string
	Location string // "body" or "header:<name>"
	Context  string // "href", "src", "script_src", "form_action", "meta_tag", "base_href", "json_value", "plain_text", "location_header", "set_cookie", "response_header"
	Dangerous bool
}

// VerbTamperResult records HTTP method discovery and verb tampering outcomes
type VerbTamperResult struct {
	AllowedMethods   []string
	DangerousMethods []string
	TraceEnabled     bool
	TraceReflects    bool
	VerbBypasses     []VerbBypass
}

// VerbBypass records a successful verb tampering auth bypass
type VerbBypass struct {
	Method     string
	StatusCode int
}

// HostInjectionResult records a host header injection finding
type HostInjectionResult struct {
	Header  string
	Canary  string
	Context string // "body_link", "location_redirect", "meta_tag", "base_href"
	Impact  string // "cache_poisoning", "password_reset_poisoning", "open_redirect"
}

// generateCanary creates a unique canary string using crypto/rand
func generateCanary() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback — should never happen with crypto/rand
		return fmt.Sprintf("hh-%d", time.Now().UnixNano())
	}
	return "hh-" + hex.EncodeToString(b)
}

// RunRecon orchestrates all reconnaissance probes
func RunRecon(client *http.Client, config *ScanConfig, baseline *ResponseContext, profile *BaselineProfile) *ReconResult {
	result := &ReconResult{}

	fmt.Println("\033[0;34m[RECON]\033[0m Starting reconnaissance phase...")

	// A) Active Reflection Probing
	reflections, reqCount := runReflectionProbes(client, config, baseline)
	result.Reflections = reflections
	result.TotalRequests += reqCount

	// B) HTTP Method Discovery & Verb Tampering
	verbResult, reqCount := runMethodDiscovery(client, config, baseline)
	result.VerbTamper = verbResult
	result.TotalRequests += reqCount

	// C) Host Header Injection Analysis
	hostResults, reqCount := runHostInjectionProbes(client, config, baseline)
	result.HostInjections = hostResults
	result.TotalRequests += reqCount

	fmt.Printf("\033[0;34m[RECON]\033[0m Reconnaissance complete (%d requests)\n", result.TotalRequests)

	return result
}

// runReflectionProbes sends canary values via common headers and checks where they appear
func runReflectionProbes(client *http.Client, config *ScanConfig, baseline *ResponseContext) ([]ReflectionHit, int) {
	canary := generateCanary()
	var hits []ReflectionHit
	reqCount := 0

	probeHeaders := []struct {
		name  string
		value string
	}{
		{"X-Forwarded-Host", canary + ".example.com"},
		{"X-Forwarded-For", canary},
		{"Forwarded", "for=" + canary + ";host=" + canary + ".example.com"},
		{"X-Original-URL", "/" + canary},
		{"Referer", "https://" + canary + ".example.com/path"},
		{"X-Custom-Header", canary},
		{"User-Agent", "Mozilla/5.0 " + canary},
		{"X-Forwarded-Proto", canary},
		{"X-Forwarded-Port", canary},
		{"Host", canary + ".example.com"},
	}

	for _, probe := range probeHeaders {
		ctx := NewRequestContext(config.URL, config.Method)
		for k, v := range config.Headers {
			ctx.AddHeader(k, v)
		}

		// For Host header, we use the special override
		if probe.name == "Host" {
			ctx.AddHeader("Host", probe.value)
		} else {
			ctx.AddHeader(probe.name, probe.value)
		}

		resp, err := ctx.Execute(client)
		reqCount++
		if err != nil {
			continue
		}

		// Check body for canary reflection
		body := string(resp.Body)
		if strings.Contains(body, canary) {
			contexts := analyzeCanaryContext(body, canary)
			for _, c := range contexts {
				dangerous := isDangerousReflectionContext(c)
				hits = append(hits, ReflectionHit{
					Header:    probe.name,
					Canary:    canary,
					Location:  "body",
					Context:   c,
					Dangerous: dangerous,
				})
			}
		}

		// Check Location header
		locationVal := getHeaderValue(resp.Headers, "location")
		if strings.Contains(locationVal, canary) {
			hits = append(hits, ReflectionHit{
				Header:    probe.name,
				Canary:    canary,
				Location:  "header:Location",
				Context:   "location_header",
				Dangerous: true,
			})
		}

		// Check Set-Cookie headers
		for k, vals := range resp.Headers {
			if strings.EqualFold(k, "set-cookie") {
				for _, v := range vals {
					if strings.Contains(v, canary) {
						hits = append(hits, ReflectionHit{
							Header:    probe.name,
							Canary:    canary,
							Location:  "header:Set-Cookie",
							Context:   "set_cookie",
							Dangerous: true,
						})
					}
				}
			}
		}

		// Check all other response headers
		for k, vals := range resp.Headers {
			kl := strings.ToLower(k)
			if kl == "location" || kl == "set-cookie" {
				continue // Already checked above
			}
			for _, v := range vals {
				if strings.Contains(v, canary) {
					hits = append(hits, ReflectionHit{
						Header:    probe.name,
						Canary:    canary,
						Location:  "header:" + k,
						Context:   "response_header",
						Dangerous: false,
					})
				}
			}
		}
	}

	if len(hits) > 0 {
		fmt.Printf("\033[0;32m[RECON]\033[0m Found %d reflection(s) across %d header(s)\n",
			len(hits), countUniqueHeaders(hits))
	} else {
		fmt.Println("\033[0;34m[RECON]\033[0m No header reflections detected")
	}

	return hits, reqCount
}

// runMethodDiscovery sends OPTIONS and tests verb tampering on auth-denied endpoints
func runMethodDiscovery(client *http.Client, config *ScanConfig, baseline *ResponseContext) (*VerbTamperResult, int) {
	result := &VerbTamperResult{}
	reqCount := 0

	// Send OPTIONS to discover allowed methods
	optCtx := NewRequestContext(config.URL, "OPTIONS")
	for k, v := range config.Headers {
		optCtx.AddHeader(k, v)
	}

	optResp, err := optCtx.Execute(client)
	reqCount++
	if err == nil {
		allowHeader := getHeaderValue(optResp.Headers, "allow")
		if allowHeader != "" {
			methods := strings.Split(allowHeader, ",")
			for _, m := range methods {
				m = strings.TrimSpace(m)
				if m != "" {
					result.AllowedMethods = append(result.AllowedMethods, m)
				}
			}
		}
		// Also check Access-Control-Allow-Methods
		acam := getHeaderValue(optResp.Headers, "access-control-allow-methods")
		if acam != "" && allowHeader == "" {
			methods := strings.Split(acam, ",")
			for _, m := range methods {
				m = strings.TrimSpace(m)
				if m != "" {
					result.AllowedMethods = append(result.AllowedMethods, m)
				}
			}
		}
	}

	// Identify dangerous methods
	dangerousList := map[string]bool{"PUT": true, "DELETE": true, "TRACE": true, "CONNECT": true, "PATCH": true}
	for _, m := range result.AllowedMethods {
		if dangerousList[strings.ToUpper(m)] {
			result.DangerousMethods = append(result.DangerousMethods, m)
		}
	}

	// Test TRACE for cross-site tracing (XST)
	traceCtx := NewRequestContext(config.URL, "TRACE")
	for k, v := range config.Headers {
		traceCtx.AddHeader(k, v)
	}
	traceCtx.AddHeader("X-HHunter-Trace", generateCanary())

	traceResp, err := traceCtx.Execute(client)
	reqCount++
	if err == nil && traceResp.StatusCode == 200 {
		result.TraceEnabled = true
		if strings.Contains(string(traceResp.Body), "X-HHunter-Trace") {
			result.TraceReflects = true
		}
	}

	// Verb tampering: if baseline is 401/403, test other methods for auth bypass
	if baseline.StatusCode == 401 || baseline.StatusCode == 403 {
		verbsToTest := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}
		for _, verb := range verbsToTest {
			if strings.EqualFold(verb, config.Method) {
				continue // Skip the original method
			}

			verbCtx := NewRequestContext(config.URL, verb)
			for k, v := range config.Headers {
				verbCtx.AddHeader(k, v)
			}

			verbResp, err := verbCtx.Execute(client)
			reqCount++
			if err != nil {
				continue
			}

			// Auth bypass: went from 401/403 to 2xx
			if verbResp.StatusCode >= 200 && verbResp.StatusCode < 300 {
				result.VerbBypasses = append(result.VerbBypasses, VerbBypass{
					Method:     verb,
					StatusCode: verbResp.StatusCode,
				})
			}
		}
	}

	// Print summary
	if len(result.AllowedMethods) > 0 {
		fmt.Printf("\033[0;32m[RECON]\033[0m Allowed methods: %s\n", strings.Join(result.AllowedMethods, ", "))
	}
	if len(result.DangerousMethods) > 0 {
		fmt.Printf("\033[0;33m[RECON]\033[0m Dangerous methods enabled: %s\n", strings.Join(result.DangerousMethods, ", "))
	}
	if result.TraceEnabled {
		if result.TraceReflects {
			fmt.Println("\033[0;31m[RECON]\033[0m TRACE enabled with input reflection (XST risk)")
		} else {
			fmt.Println("\033[0;33m[RECON]\033[0m TRACE method enabled")
		}
	}
	if len(result.VerbBypasses) > 0 {
		for _, vb := range result.VerbBypasses {
			fmt.Printf("\033[0;31m[RECON]\033[0m Verb tamper bypass: %s -> %d (baseline: %d)\n",
				vb.Method, vb.StatusCode, baseline.StatusCode)
		}
	}

	return result, reqCount
}

// runHostInjectionProbes tests host header injection vectors
func runHostInjectionProbes(client *http.Client, config *ScanConfig, baseline *ResponseContext) ([]HostInjectionResult, int) {
	canary := generateCanary()
	canaryHost := canary + ".attacker.com"
	var results []HostInjectionResult
	reqCount := 0

	hostHeaders := []string{
		"X-Forwarded-Host",
		"X-Host",
		"X-Original-Host",
		"X-Forwarded-Server",
		"X-HTTP-Host-Override",
		"Forwarded",
	}

	for _, header := range hostHeaders {
		ctx := NewRequestContext(config.URL, config.Method)
		for k, v := range config.Headers {
			ctx.AddHeader(k, v)
		}

		if header == "Forwarded" {
			ctx.AddHeader(header, "host="+canaryHost)
		} else {
			ctx.AddHeader(header, canaryHost)
		}

		resp, err := ctx.Execute(client)
		reqCount++
		if err != nil {
			continue
		}

		body := string(resp.Body)
		bodyLower := strings.ToLower(body)

		// Check if canary host appears in body links/tags
		if strings.Contains(body, canaryHost) || strings.Contains(body, canary) {
			context, impact := classifyHostInjection(bodyLower, canary, canaryHost)
			if context != "" {
				results = append(results, HostInjectionResult{
					Header:  header,
					Canary:  canaryHost,
					Context: context,
					Impact:  impact,
				})
			}
		}

		// Check Location header for redirect poisoning
		location := getHeaderValue(resp.Headers, "location")
		if strings.Contains(location, canaryHost) || strings.Contains(location, canary) {
			results = append(results, HostInjectionResult{
				Header:  header,
				Canary:  canaryHost,
				Context: "location_redirect",
				Impact:  "open_redirect",
			})
		}
	}

	if len(results) > 0 {
		for _, r := range results {
			fmt.Printf("\033[0;31m[RECON]\033[0m Host injection via %s -> %s (%s)\n",
				r.Header, r.Context, r.Impact)
		}
	} else {
		fmt.Println("\033[0;34m[RECON]\033[0m No host header injection detected")
	}

	return results, reqCount
}

// classifyHostInjection determines the context and impact of host header injection
func classifyHostInjection(bodyLower, canary, canaryHost string) (string, string) {
	// Check base href
	baseHrefPattern := regexp.MustCompile(`<base\s+[^>]*href\s*=\s*["']?[^"']*` + regexp.QuoteMeta(canary))
	if baseHrefPattern.MatchString(bodyLower) {
		return "base_href", "cache_poisoning"
	}

	// Check meta refresh/redirect
	metaPattern := regexp.MustCompile(`<meta\s+[^>]*(?:url|content)\s*=\s*["']?[^"']*` + regexp.QuoteMeta(canary))
	if metaPattern.MatchString(bodyLower) {
		return "meta_tag", "cache_poisoning"
	}

	// Check href attributes (links, stylesheets)
	hrefPattern := regexp.MustCompile(`href\s*=\s*["']?[^"']*` + regexp.QuoteMeta(canary))
	if hrefPattern.MatchString(bodyLower) {
		return "body_link", "cache_poisoning"
	}

	// Check src attributes (scripts, images)
	srcPattern := regexp.MustCompile(`src\s*=\s*["']?[^"']*` + regexp.QuoteMeta(canary))
	if srcPattern.MatchString(bodyLower) {
		return "body_link", "cache_poisoning"
	}

	// Check form action
	actionPattern := regexp.MustCompile(`action\s*=\s*["']?[^"']*` + regexp.QuoteMeta(canary))
	if actionPattern.MatchString(bodyLower) {
		return "body_link", "password_reset_poisoning"
	}

	// Generic body presence — still relevant for cache poisoning
	if strings.Contains(bodyLower, canary) {
		return "body_link", "cache_poisoning"
	}

	return "", ""
}

// analyzeCanaryContext determines all contexts where a canary appears in the body
func analyzeCanaryContext(body, canary string) []string {
	var contexts []string
	bodyLower := strings.ToLower(body)
	canaryLower := strings.ToLower(canary)
	seen := make(map[string]bool)

	addContext := func(ctx string) {
		if !seen[ctx] {
			seen[ctx] = true
			contexts = append(contexts, ctx)
		}
	}

	// Check script src
	scriptSrcPattern := regexp.MustCompile(`<script[^>]*\ssrc\s*=\s*["']?[^"'>]*` + regexp.QuoteMeta(canaryLower))
	if scriptSrcPattern.MatchString(bodyLower) {
		addContext("script_src")
	}

	// Check base href
	basePattern := regexp.MustCompile(`<base[^>]*\shref\s*=\s*["']?[^"'>]*` + regexp.QuoteMeta(canaryLower))
	if basePattern.MatchString(bodyLower) {
		addContext("base_href")
	}

	// Check form action
	actionPattern := regexp.MustCompile(`<form[^>]*\saction\s*=\s*["']?[^"'>]*` + regexp.QuoteMeta(canaryLower))
	if actionPattern.MatchString(bodyLower) {
		addContext("form_action")
	}

	// Check href (links, stylesheets)
	hrefPattern := regexp.MustCompile(`href\s*=\s*["']?[^"'>]*` + regexp.QuoteMeta(canaryLower))
	if hrefPattern.MatchString(bodyLower) {
		addContext("href")
	}

	// Check src (images, iframes, etc.)
	srcPattern := regexp.MustCompile(`src\s*=\s*["']?[^"'>]*` + regexp.QuoteMeta(canaryLower))
	if srcPattern.MatchString(bodyLower) && !seen["script_src"] {
		addContext("src")
	}

	// Check meta tags
	metaPattern := regexp.MustCompile(`<meta[^>]*` + regexp.QuoteMeta(canaryLower))
	if metaPattern.MatchString(bodyLower) {
		addContext("meta_tag")
	}

	// Check JSON context
	jsonPattern := regexp.MustCompile(`"[^"]*"\s*:\s*"[^"]*` + regexp.QuoteMeta(canary))
	if jsonPattern.MatchString(body) {
		addContext("json_value")
	}

	// If no specific context found, it's plain text
	if len(contexts) == 0 && strings.Contains(body, canary) {
		addContext("plain_text")
	}

	return contexts
}

// isDangerousReflectionContext returns true if the reflection context poses a security risk
func isDangerousReflectionContext(ctx string) bool {
	switch ctx {
	case "script_src", "form_action", "base_href", "location_header", "set_cookie":
		return true
	default:
		return false
	}
}

// ReconToFindings converts recon results into Finding structs
func ReconToFindings(recon *ReconResult) []Finding {
	var findings []Finding

	// Dangerous reflections
	for _, hit := range recon.Reflections {
		if !hit.Dangerous {
			continue
		}

		severity := "Medium"
		cvss := 6.1
		cwe := "CWE-79"
		confidence := 0.75

		switch hit.Context {
		case "script_src":
			severity = "High"
			cvss = 8.0
			confidence = 0.85
		case "base_href":
			severity = "High"
			cvss = 7.5
			cwe = "CWE-79"
			confidence = 0.8
		case "form_action":
			severity = "High"
			cvss = 7.5
			cwe = "CWE-601"
			confidence = 0.8
		case "location_header":
			severity = "High"
			cvss = 7.5
			cwe = "CWE-601"
			confidence = 0.85
		case "set_cookie":
			severity = "Medium"
			cvss = 5.3
			cwe = "CWE-113"
			confidence = 0.7
		}

		findings = append(findings, Finding{
			Header:          hit.Header,
			Payload:         hit.Canary,
			Impact:          fmt.Sprintf("Header reflection in %s context via %s", hit.Context, hit.Location),
			Confidence:      confidenceLabel(confidence),
			ConfidenceScore: confidence,
			Evidence: map[string]string{
				"reflection_location": hit.Location,
				"reflection_context":  hit.Context,
				"canary":              hit.Canary,
			},
			Category:    "Recon",
			Severity:    severity,
			CVSS:        cvss,
			CWE:         cwe,
			Remediation: "Never reflect user-supplied header values without proper encoding. Implement output encoding and Content-Security-Policy.",
			Timestamp:   time.Now(),
			ReconSource: "reflection_probe",
		})
	}

	// Verb tamper bypasses
	if recon.VerbTamper != nil {
		for _, vb := range recon.VerbTamper.VerbBypasses {
			findings = append(findings, Finding{
				Header:          "HTTP Method",
				Payload:         vb.Method,
				Impact:          fmt.Sprintf("Authentication bypass via HTTP verb tampering (%s -> %d)", vb.Method, vb.StatusCode),
				Confidence:      "High",
				ConfidenceScore: 0.8,
				Evidence: map[string]string{
					"method":      vb.Method,
					"status_code": fmt.Sprintf("%d", vb.StatusCode),
					"verb_tamper": "true",
				},
				Category:    "Recon",
				Severity:    "Critical",
				CVSS:        9.8,
				CWE:         "CWE-287",
				Remediation: "Enforce authentication on all HTTP methods. Do not rely on method-based access control. Validate credentials regardless of request method.",
				Timestamp:   time.Now(),
				ReconSource: "verb_tamper",
			})
		}

		// TRACE with reflection = XST
		if recon.VerbTamper.TraceEnabled && recon.VerbTamper.TraceReflects {
			findings = append(findings, Finding{
				Header:          "HTTP Method",
				Payload:         "TRACE",
				Impact:          "TRACE method enabled with input reflection (Cross-Site Tracing)",
				Confidence:      "High",
				ConfidenceScore: 0.8,
				Evidence: map[string]string{
					"trace_enabled":  "true",
					"trace_reflects": "true",
				},
				Category:    "Recon",
				Severity:    "Medium",
				CVSS:        5.3,
				CWE:         "CWE-693",
				Remediation: "Disable TRACE method on the web server. In Apache: TraceEnable Off. In Nginx: deny TRACE in location blocks.",
				Timestamp:   time.Now(),
				ReconSource: "method_discovery",
			})
		}

		// Dangerous methods enabled
		for _, dm := range recon.VerbTamper.DangerousMethods {
			if strings.EqualFold(dm, "TRACE") && recon.VerbTamper.TraceEnabled {
				continue // Already reported above
			}
			findings = append(findings, Finding{
				Header:          "HTTP Method",
				Payload:         dm,
				Impact:          fmt.Sprintf("Dangerous HTTP method %s enabled", dm),
				Confidence:      "Medium",
				ConfidenceScore: 0.6,
				Evidence: map[string]string{
					"method":  dm,
					"allowed": "true",
				},
				Category:    "Recon",
				Severity:    "Low",
				CVSS:        3.7,
				CWE:         "CWE-749",
				Remediation: "Disable unnecessary HTTP methods. Only allow GET, POST, and HEAD unless other methods are required.",
				Timestamp:   time.Now(),
				ReconSource: "method_discovery",
			})
		}
	}

	// Host header injections
	for _, hi := range recon.HostInjections {
		severity := "High"
		cvss := 7.5
		cwe := "CWE-644"
		confidence := 0.8

		switch hi.Impact {
		case "password_reset_poisoning":
			severity = "Critical"
			cvss = 9.1
			cwe = "CWE-640"
			confidence = 0.85
		case "open_redirect":
			severity = "High"
			cvss = 7.5
			cwe = "CWE-601"
			confidence = 0.85
		case "cache_poisoning":
			severity = "High"
			cvss = 7.5
			cwe = "CWE-444"
			confidence = 0.75
		}

		findings = append(findings, Finding{
			Header:          hi.Header,
			Payload:         hi.Canary,
			Impact:          fmt.Sprintf("Host header injection via %s (%s in %s)", hi.Header, hi.Impact, hi.Context),
			Confidence:      confidenceLabel(confidence),
			ConfidenceScore: confidence,
			Evidence: map[string]string{
				"injection_context": hi.Context,
				"impact":            hi.Impact,
				"canary":            hi.Canary,
			},
			Category:    "Recon",
			Severity:    severity,
			CVSS:        cvss,
			CWE:         cwe,
			Remediation: "Configure the application to use a hardcoded server name. Reject or ignore X-Forwarded-Host and similar headers from untrusted sources.",
			Timestamp:   time.Now(),
			ReconSource: "host_injection",
		})
	}

	return findings
}

// ToSummary converts a ReconResult into a ReconSummary for the scan result
func (r *ReconResult) ToSummary() *ReconSummary {
	summary := &ReconSummary{}

	// Collect unique reflected headers
	headerSet := make(map[string]bool)
	for _, hit := range r.Reflections {
		headerSet[hit.Header] = true
	}
	for h := range headerSet {
		summary.ReflectedHeaders = append(summary.ReflectedHeaders, h)
	}

	if r.VerbTamper != nil {
		summary.AllowedMethods = r.VerbTamper.AllowedMethods
		summary.DangerousMethods = r.VerbTamper.DangerousMethods
		summary.TraceEnabled = r.VerbTamper.TraceEnabled
		summary.VerbTamperBypasses = len(r.VerbTamper.VerbBypasses)
	}

	hostSet := make(map[string]bool)
	for _, hi := range r.HostInjections {
		hostSet[hi.Header] = true
	}
	for h := range hostSet {
		summary.HostInjectable = append(summary.HostInjectable, h)
	}

	return summary
}

// ReflectedHeaderSet returns a set of header names that were found to reflect
func (r *ReconResult) ReflectedHeaderSet() map[string]bool {
	set := make(map[string]bool)
	for _, hit := range r.Reflections {
		set[strings.ToLower(hit.Header)] = true
	}
	// Also include host-injectable headers
	for _, hi := range r.HostInjections {
		set[strings.ToLower(hi.Header)] = true
	}
	return set
}

// countUniqueHeaders returns the number of unique headers in a slice of ReflectionHits
func countUniqueHeaders(hits []ReflectionHit) int {
	seen := make(map[string]bool)
	for _, h := range hits {
		seen[h.Header] = true
	}
	return len(seen)
}

// confidenceLabel converts a numeric confidence to a human-readable label
func confidenceLabel(score float64) string {
	if score >= 0.8 {
		return "Confirmed"
	}
	if score >= 0.6 {
		return "High"
	}
	if score >= 0.4 {
		return "Medium"
	}
	return "Low"
}
