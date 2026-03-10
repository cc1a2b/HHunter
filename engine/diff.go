package engine

import (
	"encoding/json"
	"math"
	"regexp"
	"strings"
)

type EvidenceItem struct {
	Type        string  // e.g. "status_change", "auth_bypass", "reflection"
	Description string  // human-readable description
	Confidence  float64 // 0.0 - 1.0
	Severity    string  // Critical, High, Medium, Low, Info
}

type DiffResult struct {
	StatusChanged      bool
	BodyHashChanged    bool
	NewJSONKeys        []string
	SizeChangeRatio    float64
	TimingDeltaMS      int64
	HeadersAdded       []string
	HeadersRemoved     []string
	PrivilegeElevate   bool
	AuthBypass         bool
	HeaderReflection   bool
	ReflectedValue     string
	SensitiveDataFound []string
	CORSMisconfigured  bool
	CORSDetails        string
	InfoDisclosure     []string
	TimingAnomaly      string

	// Enhanced response tracking
	LocationHeader     string
	LocationChanged    bool
	SetCookiePresent   bool
	SetCookieValues    []string
	ContentTypeChanged bool
	AuthChallengeGone  bool

	// New: evidence-based scoring
	Evidence         []EvidenceItem
	TotalConfidence  float64
	HighestSeverity  string
	EvidenceCount    int
	ReflectionContext string // "html_tag", "html_attr", "js_context", "json_value", "header", "safe"
}

// BaselineProfile holds statistical data from multiple baseline requests
type BaselineProfile struct {
	StatusCode       int
	StatusConsistent bool
	BodyHashes       []string
	BodyConsistent   bool
	AvgSize          float64
	SizeStdDev       float64
	AvgTiming        float64
	TimingStdDev     float64
	ConsistentHeaders map[string]bool // headers that appear in all baselines
	BaselineKeys     []string        // JSON keys from baseline
	BaselineSensitive []string       // sensitive patterns already in baseline
	Responses        []*ResponseContext

	// Volatile field tracking (Rule #1)
	VolatileHeaders map[string]bool // headers whose values change across samples
	VolatileCookies map[string]bool // cookie names with rotating values
}

func NewBaselineProfile(responses []*ResponseContext) *BaselineProfile {
	if len(responses) == 0 {
		return &BaselineProfile{}
	}

	bp := &BaselineProfile{
		StatusCode:        responses[0].StatusCode,
		StatusConsistent:  true,
		ConsistentHeaders: make(map[string]bool),
		Responses:         responses,
	}

	// Check status consistency
	for _, r := range responses {
		if r.StatusCode != bp.StatusCode {
			bp.StatusConsistent = false
			break
		}
	}

	// Collect body hashes and check consistency
	hashSet := make(map[string]bool)
	for _, r := range responses {
		bp.BodyHashes = append(bp.BodyHashes, r.BodyHash)
		hashSet[r.BodyHash] = true
	}
	bp.BodyConsistent = len(hashSet) == 1

	// Calculate size stats
	sizes := make([]float64, len(responses))
	for i, r := range responses {
		sizes[i] = float64(r.ContentLength)
	}
	bp.AvgSize = mean(sizes)
	bp.SizeStdDev = stddev(sizes)

	// Calculate timing stats
	timings := make([]float64, len(responses))
	for i, r := range responses {
		timings[i] = float64(r.TimingMS)
	}
	bp.AvgTiming = mean(timings)
	bp.TimingStdDev = stddev(timings)

	// Find headers present in ALL baselines
	if len(responses) > 0 {
		for k := range responses[0].Headers {
			bp.ConsistentHeaders[strings.ToLower(k)] = true
		}
		for i := 1; i < len(responses); i++ {
			current := make(map[string]bool)
			for k := range responses[i].Headers {
				current[strings.ToLower(k)] = true
			}
			for k := range bp.ConsistentHeaders {
				if !current[k] {
					delete(bp.ConsistentHeaders, k)
				}
			}
		}
	}

	// Extract baseline JSON keys (union of all)
	keySet := make(map[string]bool)
	for _, r := range responses {
		for _, k := range extractJSONKeys(r.Body) {
			keySet[k] = true
		}
	}
	for k := range keySet {
		bp.BaselineKeys = append(bp.BaselineKeys, k)
	}

	// Extract baseline sensitive patterns (union of all)
	sensitiveSet := make(map[string]bool)
	for _, r := range responses {
		for _, s := range detectSensitiveDataRaw(r) {
			sensitiveSet[s] = true
		}
	}
	for s := range sensitiveSet {
		bp.BaselineSensitive = append(bp.BaselineSensitive, s)
	}

	// --- Volatile field detection (Rule #1) ---
	bp.VolatileHeaders = make(map[string]bool)
	bp.VolatileCookies = make(map[string]bool)

	// Always-volatile headers — excluded from ALL comparisons regardless
	alwaysVolatile := []string{
		"set-cookie", "date", "etag", "x-request-id", "cf-ray",
		"x-trace-id", "age", "x-amz-request-id", "x-amz-cf-id",
		"x-amzn-trace-id", "x-amz-cf-pop",
		"x-correlation-id", "x-b3-traceid", "x-b3-spanid",
		"traceparent", "tracestate", "expires", "x-request-start",
		"x-runtime", "x-timer", "x-envoy-upstream-service-time",
		"x-ruxit-js-agent", "x-oneagent-js-injection",
		"x-cloud-trace-context", "x-ms-request-id",
		"x-edge-ip", "x-edge-location", "x-cache",
		"x-cache-hits", "x-served-by", "x-varnish",
		"x-fastly-request-id", "fastly-debug-digest",
	}
	for _, h := range alwaysVolatile {
		bp.VolatileHeaders[h] = true
	}

	// Pattern-based volatile detection: any header containing these substrings
	// is always volatile regardless of whether it changed between samples
	volatilePatterns := []string{
		"token", "nonce", "seed", "csrf", "session", "timestamp",
		"request-id", "requestid", "trace-id", "traceid",
		"correlation", "txid", "transaction-id",
	}
	// We'll apply this after collecting all headers below

	// Detect headers whose values change between baseline samples
	if len(responses) > 1 {
		// Build header fingerprint per sample: lowercase name → joined values
		type hfp map[string]string
		var fingerprints []hfp
		for _, r := range responses {
			fp := make(hfp)
			for k, vals := range r.Headers {
				fp[strings.ToLower(k)] = strings.Join(vals, "\x00")
			}
			fingerprints = append(fingerprints, fp)
		}

		// Collect all header names
		allHeaders := make(map[string]bool)
		for _, fp := range fingerprints {
			for k := range fp {
				allHeaders[k] = true
			}
		}

		// Header is volatile if its value differs between any two samples
		for h := range allHeaders {
			if bp.VolatileHeaders[h] {
				continue
			}
			ref, refExists := fingerprints[0][h]
			for i := 1; i < len(fingerprints); i++ {
				val, exists := fingerprints[i][h]
				if refExists != exists || ref != val {
					bp.VolatileHeaders[h] = true
					break
				}
			}
		}
	}

	// Apply pattern-based volatile detection to all known headers
	if len(responses) > 0 {
		allKnownHeaders := make(map[string]bool)
		for _, r := range responses {
			for k := range r.Headers {
				allKnownHeaders[strings.ToLower(k)] = true
			}
		}
		for h := range allKnownHeaders {
			if bp.VolatileHeaders[h] {
				continue
			}
			for _, pat := range volatilePatterns {
				if strings.Contains(h, pat) {
					bp.VolatileHeaders[h] = true
					break
				}
			}
		}
	}

	// Detect volatile cookie names from Set-Cookie headers
	cookieNameValues := make(map[string]map[string]bool) // name → set of full values
	for _, r := range responses {
		for k, vals := range r.Headers {
			if !strings.EqualFold(k, "set-cookie") {
				continue
			}
			for _, v := range vals {
				name := cookieNameFromSetCookie(v)
				if name == "" {
					continue
				}
				if cookieNameValues[name] == nil {
					cookieNameValues[name] = make(map[string]bool)
				}
				cookieNameValues[name][v] = true
			}
		}
	}
	for name, vals := range cookieNameValues {
		if len(vals) > 1 {
			bp.VolatileCookies[name] = true
		}
	}

	return bp
}

func CalculateDiff(baseline, mutated *ResponseContext) *DiffResult {
	return CalculateDiffWithProfile(baseline, mutated, nil)
}

func CalculateDiffWithProfile(baseline, mutated *ResponseContext, profile *BaselineProfile) *DiffResult {
	diff := &DiffResult{
		Evidence: []EvidenceItem{},
	}

	diff.StatusChanged = baseline.StatusCode != mutated.StatusCode
	diff.BodyHashChanged = baseline.BodyHash != mutated.BodyHash
	diff.TimingDeltaMS = mutated.TimingMS - baseline.TimingMS

	if baseline.ContentLength > 0 {
		diff.SizeChangeRatio = float64(mutated.ContentLength) / float64(baseline.ContentLength)
	} else if mutated.ContentLength > 0 {
		diff.SizeChangeRatio = 2.0
	} else {
		diff.SizeChangeRatio = 1.0
	}

	baselineKeys := extractJSONKeys(baseline.Body)
	mutatedKeys := extractJSONKeys(mutated.Body)

	// Use profile keys if available (more comprehensive)
	if profile != nil && len(profile.BaselineKeys) > 0 {
		baselineKeys = profile.BaselineKeys
	}
	diff.NewJSONKeys = findNewKeys(baselineKeys, mutatedKeys)

	diff.HeadersAdded = findNewHeaders(baseline.Headers, mutated.Headers)
	diff.HeadersRemoved = findRemovedHeaders(baseline.Headers, mutated.Headers)

	diff.AuthBypass = detectAuthBypassStrict(baseline, mutated, profile)
	diff.PrivilegeElevate = detectPrivilegeElevationStrict(baseline, mutated, profile)
	diff.SensitiveDataFound = detectSensitiveDataDelta(baseline, mutated, profile)
	diff.CORSMisconfigured, diff.CORSDetails = detectCORSMisconfigStrict(baseline, mutated)
	diff.InfoDisclosure = detectInfoDisclosureStrict(baseline, mutated, profile)
	diff.TimingAnomaly = detectTimingAnomalyStrict(baseline, mutated, profile)

	// Enhanced response tracking: Location header
	diff.LocationHeader = getHeaderValue(mutated.Headers, "location")
	if diff.LocationHeader != "" {
		baselineLocation := getHeaderValue(baseline.Headers, "location")
		diff.LocationChanged = diff.LocationHeader != baselineLocation
	}

	// Enhanced response tracking: Set-Cookie
	for k, vals := range mutated.Headers {
		if strings.EqualFold(k, "set-cookie") {
			diff.SetCookiePresent = true
			baselineCookies := make(map[string]bool)
			for bk, bvals := range baseline.Headers {
				if strings.EqualFold(bk, "set-cookie") {
					for _, bv := range bvals {
						baselineCookies[bv] = true
					}
				}
			}
			for _, v := range vals {
				if !baselineCookies[v] {
					diff.SetCookieValues = append(diff.SetCookieValues, v)
				}
			}
			break
		}
	}

	// Enhanced response tracking: Content-Type changed
	baselineCT := getHeaderValue(baseline.Headers, "content-type")
	mutatedCT := getHeaderValue(mutated.Headers, "content-type")
	if baselineCT != "" && mutatedCT != "" && baselineCT != mutatedCT {
		diff.ContentTypeChanged = true
	}

	// Enhanced response tracking: WWW-Authenticate challenge gone
	baselineAuth := getHeaderValue(baseline.Headers, "www-authenticate")
	mutatedAuth := getHeaderValue(mutated.Headers, "www-authenticate")
	if baselineAuth != "" && mutatedAuth == "" {
		diff.AuthChallengeGone = true
	}

	// --- Filter volatile fields (Rule #1) ---
	if profile != nil && len(profile.VolatileHeaders) > 0 {
		diff.HeadersAdded = filterNonVolatile(diff.HeadersAdded, profile.VolatileHeaders)
		diff.HeadersRemoved = filterNonVolatile(diff.HeadersRemoved, profile.VolatileHeaders)

		// Filter volatile cookies from SetCookieValues
		if len(profile.VolatileCookies) > 0 && len(diff.SetCookieValues) > 0 {
			var filteredCookies []string
			for _, sc := range diff.SetCookieValues {
				name := cookieNameFromSetCookie(sc)
				if !profile.VolatileCookies[name] {
					filteredCookies = append(filteredCookies, sc)
				}
			}
			diff.SetCookieValues = filteredCookies
			diff.SetCookiePresent = len(filteredCookies) > 0
		}

		// Filter volatile headers from InfoDisclosure
		if len(diff.InfoDisclosure) > 0 {
			var filteredInfo []string
			for _, d := range diff.InfoDisclosure {
				colonIdx := strings.Index(d, ": ")
				if colonIdx > 0 {
					headerName := strings.ToLower(d[:colonIdx])
					if profile.VolatileHeaders[headerName] {
						continue
					}
				}
				filteredInfo = append(filteredInfo, d)
			}
			diff.InfoDisclosure = filteredInfo
		}
	}

	return diff
}

// CheckHeaderReflection performs context-aware reflection detection.
// Returns (reflected, location, context) where context describes if
// the reflection is in a dangerous position.
func CheckHeaderReflection(mutation Mutation, resp *ResponseContext) (bool, string) {
	return checkHeaderReflectionStrict(mutation, resp)
}

func checkHeaderReflectionStrict(mutation Mutation, resp *ResponseContext) (bool, string) {
	value := mutation.Value

	// Minimum 8 characters to avoid matching common words like "true", "null", "test", "admin"
	if len(value) < 8 {
		return false, ""
	}

	// Skip values that are common in responses naturally — infrastructure, protocols, CDN identifiers
	skipValues := []string{
		"true", "false", "null", "undefined", "admin", "test",
		"localhost", "127.0.0.1", "application/json", "application/xml",
		"text/html", "text/plain", "utf-8", "gzip", "deflate",
		"keep-alive", "close", "no-cache", "no-store",
		"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH",
		// CDN / server identifiers that naturally appear in response headers
		"cloudflare", "akamai", "fastly", "varnish", "nginx", "apache",
		"cloudfront", "incapsula", "sucuri", "stackpath", "imperva",
		"AES256", "internal", "default", "bypass",
	}
	lowerValue := strings.ToLower(value)
	for _, skip := range skipValues {
		if lowerValue == skip {
			return false, ""
		}
	}

	body := string(resp.Body)

	// Check body reflection with context analysis
	if strings.Contains(body, value) {
		ctx := analyzeReflectionContext(body, value)
		if ctx != "safe" {
			return true, "body:" + ctx
		}
		return false, ""
	}

	// Check header reflection — must be in a non-infrastructure header
	// and the value must not naturally belong to a known server/CDN header
	infrastructureHeaders := map[string]bool{
		"server": true, "via": true, "x-powered-by": true,
		"x-cache": true, "x-cache-hits": true, "x-served-by": true,
		"x-varnish": true, "x-fastly-request-id": true,
		"x-amz-cf-id": true, "x-amz-request-id": true,
		"x-azure-ref": true, "x-request-id": true,
		"x-correlation-id": true, "x-trace-id": true,
		"cf-ray": true, "cf-cache-status": true,
		"x-cdn": true, "x-edge-location": true,
		"x-backend-server": true, "x-timer": true,
		"x-envoy-upstream-service-time": true,
		"alt-svc": true, "x-runtime": true,
		"x-cloud-trace-context": true,
		"traceparent": true, "tracestate": true,
		"fastly-debug-digest": true, "x-b3-traceid": true,
		"x-b3-spanid": true,
	}

	for headerName, vals := range resp.Headers {
		hlower := strings.ToLower(headerName)
		// Skip known infrastructure/CDN headers — values here are from the server, not reflected input
		if infrastructureHeaders[hlower] {
			continue
		}
		// Skip CF-* and X-Amz-* prefixed headers entirely
		if strings.HasPrefix(hlower, "cf-") || strings.HasPrefix(hlower, "x-amz-") ||
			strings.HasPrefix(hlower, "x-azure-") || strings.HasPrefix(hlower, "x-envoy-") {
			continue
		}
		for _, v := range vals {
			if v == value {
				return true, "header:exact"
			}
		}
	}

	return false, ""
}

// analyzeReflectionContext determines the context where a value is reflected
func analyzeReflectionContext(body, value string) string {
	idx := strings.Index(body, value)
	if idx == -1 {
		return "safe"
	}

	// Get surrounding context (200 chars before and after)
	ctxStart := idx - 200
	if ctxStart < 0 {
		ctxStart = 0
	}
	ctxEnd := idx + len(value) + 200
	if ctxEnd > len(body) {
		ctxEnd = len(body)
	}
	surrounding := body[ctxStart:ctxEnd]
	surroundingLower := strings.ToLower(surrounding)

	// Check if reflected inside a JSON string value (very common, usually safe)
	beforeValue := body[ctxStart:idx]
	if isInsideJSONString(beforeValue) {
		return "safe"
	}

	// Check if inside HTML tag attribute
	if isInsideHTMLTag(surrounding, idx-ctxStart) {
		// Inside an attribute — check if it's a dangerous attribute
		if containsDangerousAttr(surroundingLower) {
			return "html_dangerous_attr"
		}
		return "html_attr"
	}

	// Check if inside script tag
	lastScriptOpen := strings.LastIndex(surroundingLower[:idx-ctxStart], "<script")
	lastScriptClose := strings.LastIndex(surroundingLower[:idx-ctxStart], "</script")
	if lastScriptOpen > lastScriptClose {
		return "js_context"
	}

	// Check if the value contains HTML-significant characters that survived
	if strings.ContainsAny(value, "<>\"'") {
		return "html_unescaped"
	}

	// Generic body reflection — not in a dangerous context
	return "safe"
}

func isInsideJSONString(before string) bool {
	// Count unescaped quotes — if odd number, we're inside a string
	trimmed := strings.TrimRight(before, " \t\n\r")
	if len(trimmed) == 0 {
		return false
	}

	// Simple heuristic: check if last non-whitespace before value is ":"
	// and the char before that is a quote — JSON key-value pattern
	quoteCount := 0
	for i := len(trimmed) - 1; i >= 0; i-- {
		if trimmed[i] == '"' && (i == 0 || trimmed[i-1] != '\\') {
			quoteCount++
		}
		// Stop counting after a reasonable lookback
		if quoteCount > 2 || (len(trimmed)-i) > 50 {
			break
		}
	}

	// If we see patterns like `"key": "VALUE` or `"key":"VALUE`
	// the value is in a JSON string
	trimmedEnd := strings.TrimRight(trimmed, " \t\n\r")
	if strings.HasSuffix(trimmedEnd, `"`) || strings.HasSuffix(trimmedEnd, `":`) {
		return false // ambiguous
	}
	if strings.HasSuffix(trimmedEnd, `:"`) || strings.HasSuffix(trimmedEnd, `: "`) {
		return true
	}

	return quoteCount%2 == 1
}

func isInsideHTMLTag(surrounding string, offset int) bool {
	before := surrounding[:offset]
	lastOpen := strings.LastIndex(before, "<")
	lastClose := strings.LastIndex(before, ">")
	return lastOpen > lastClose
}

func containsDangerousAttr(s string) bool {
	dangerous := []string{
		"onclick", "onerror", "onload", "onmouseover", "onfocus",
		"onblur", "onsubmit", "href=", "src=", "action=", "formaction=",
		"data-bind", "ng-", "v-bind", "v-on",
	}
	for _, attr := range dangerous {
		if strings.Contains(s, attr) {
			return true
		}
	}
	return false
}

// --- Auth Bypass Detection (Strict) ---

func detectAuthBypassStrict(baseline, mutated *ResponseContext, profile *BaselineProfile) bool {
	// Only consider auth bypass if baseline is an auth-denied response
	isAuthDenied := baseline.StatusCode == 401 || baseline.StatusCode == 403
	if !isAuthDenied {
		return false
	}

	// If profile shows baseline is inconsistent in status codes, don't trust this
	if profile != nil && !profile.StatusConsistent {
		return false
	}

	// Case 1: 401/403 → 2xx success (classic auth bypass)
	isSuccess := mutated.StatusCode >= 200 && mutated.StatusCode < 300

	// Case 2: 401/403 → 302/301 redirect to authenticated area (not to login page)
	isAuthRedirect := false
	if mutated.StatusCode == 301 || mutated.StatusCode == 302 || mutated.StatusCode == 307 || mutated.StatusCode == 308 {
		location := strings.ToLower(getHeaderValue(mutated.Headers, "location"))
		// Only count as auth bypass if NOT redirecting to login/auth page
		loginPatterns := []string{"/login", "/signin", "/auth", "/sso", "/oauth", "/cas/login", "/saml", "/accounts/login"}
		isLoginRedirect := false
		for _, lp := range loginPatterns {
			if strings.Contains(location, lp) {
				isLoginRedirect = true
				break
			}
		}
		// Redirect to dashboard/admin/home/api = auth bypass
		if !isLoginRedirect && location != "" {
			authAreaPatterns := []string{"/dashboard", "/admin", "/home", "/api/", "/panel", "/console", "/account", "/profile", "/settings"}
			for _, ap := range authAreaPatterns {
				if strings.Contains(location, ap) {
					isAuthRedirect = true
					break
				}
			}
			// Also treat redirect to root or relative paths without login as suspicious
			if !isAuthRedirect && (location == "/" || (!strings.Contains(location, "login") && !strings.Contains(location, "auth"))) {
				isAuthRedirect = true
			}
		}
	}

	// Case 3: 403 → 204 No Content (successful operation without response body)
	isNoContent := mutated.StatusCode == 204

	if !isSuccess && !isAuthRedirect && !isNoContent {
		return false
	}

	// For redirects and 204, this is already strong evidence
	if isAuthRedirect || isNoContent {
		return true
	}

	// For 2xx success, require evidence of actual content change
	baselineBody := strings.ToLower(string(baseline.Body))
	mutatedBody := strings.ToLower(string(mutated.Body))

	authDenyPatterns := []string{
		"unauthorized", "forbidden", "access denied", "not authenticated",
		"authentication required", "login required", "invalid token",
		"token expired", "session expired", "permission denied",
		"not authorized", "auth_required", "unauthenticated",
		"requires authentication", "401", "403",
		"you are not authorized", "insufficient permissions",
		"please log in", "must be logged in", "not_authenticated",
	}

	baselineHasDeny := false
	for _, pattern := range authDenyPatterns {
		if strings.Contains(baselineBody, pattern) {
			baselineHasDeny = true
			break
		}
	}

	mutatedHasDeny := false
	for _, pattern := range authDenyPatterns {
		if strings.Contains(mutatedBody, pattern) {
			mutatedHasDeny = true
			break
		}
	}

	// Must have: baseline has denial AND mutated does NOT have denial
	if !baselineHasDeny {
		// Baseline is 401/403 but no denial text — check size and structure evidence
		if mutated.ContentLength > 0 && baseline.ContentLength > 0 {
			ratio := float64(mutated.ContentLength) / float64(baseline.ContentLength)
			// Mutated substantially larger AND has new JSON keys = likely real content
			if ratio > 1.5 {
				return true
			}
			// Mutated has completely different structure (JSON keys)
			mutatedKeys := extractJSONKeys(mutated.Body)
			baselineKeys := extractJSONKeys(baseline.Body)
			if len(mutatedKeys) > len(baselineKeys)+3 {
				return true
			}
		}
		return false
	}

	// Strong signal: baseline has denial pattern, mutated doesn't
	if baselineHasDeny && !mutatedHasDeny {
		return true
	}

	return false
}

// --- Privilege Escalation Detection (Strict) ---

func detectPrivilegeElevationStrict(baseline, mutated *ResponseContext, profile *BaselineProfile) bool {
	baselineKeys := extractJSONKeys(baseline.Body)
	mutatedKeys := extractJSONKeys(mutated.Body)

	if profile != nil && len(profile.BaselineKeys) > 0 {
		baselineKeys = profile.BaselineKeys
	}

	// Count privilege-related keys
	baselinePriv := countPrivilegeKeys(baselineKeys)
	mutatedPriv := countPrivilegeKeys(mutatedKeys)

	// Only flag if there's a significant increase in privilege-related fields
	// AND the actual values suggest elevated privileges
	if mutatedPriv > baselinePriv+2 {
		return true
	}

	// Check for actual privilege indicators in response body
	// Must NOT be present in baseline and MUST be present in mutated
	// Use exact word boundaries to avoid matching "administrator" in documentation
	baselineBody := strings.ToLower(string(baseline.Body))
	mutatedBody := strings.ToLower(string(mutated.Body))

	// These are strong indicators that require JSON structure context
	strongIndicators := []struct {
		pattern string
		regex   *regexp.Regexp
	}{
		{"role.*admin", regexp.MustCompile(`"role"\s*:\s*"(?:admin|administrator|superuser|root)"`)},
		{"is_admin.*true", regexp.MustCompile(`"is[_-]?admin"\s*:\s*(?:true|1|"true"|"1")`)},
		{"privilege.*admin", regexp.MustCompile(`"privilege[s]?"\s*:\s*"(?:admin|elevated|root)"`)},
		{"access_level.*admin", regexp.MustCompile(`"access[_-]?level"\s*:\s*(?:"admin"|"root"|"superuser"|9|10)`)},
	}

	for _, si := range strongIndicators {
		baselineMatch := si.regex.MatchString(baselineBody)
		mutatedMatch := si.regex.MatchString(mutatedBody)
		if !baselineMatch && mutatedMatch {
			return true
		}
	}

	return false
}

func countPrivilegeKeys(keys []string) int {
	count := 0
	privilegeTerms := []string{
		"admin", "role", "permission", "privilege", "super",
		"scope", "acl", "group", "authority", "grant",
	}

	for _, key := range keys {
		lowerKey := strings.ToLower(key)
		for _, term := range privilegeTerms {
			if strings.Contains(lowerKey, term) {
				count++
				break
			}
		}
	}
	return count
}

// --- Sensitive Data Detection ---

func detectSensitiveDataRaw(resp *ResponseContext) []string {
	sensitive := []string{}
	body := string(resp.Body)

	// Only use high-confidence patterns — things that are clearly sensitive
	patterns := map[string]*regexp.Regexp{
		// Cloud credentials
		"aws_key":           regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`),
		"aws_secret":        regexp.MustCompile(`(?i)(?:aws_secret_access_key|aws_secret)\s*[=:]\s*[A-Za-z0-9/+=]{40}`),
		"gcp_key":           regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		"gcp_service_acct":  regexp.MustCompile(`"type"\s*:\s*"service_account"`),

		// Cryptographic secrets
		"private_key":       regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
		"private_key_enc":   regexp.MustCompile(`-----BEGIN ENCRYPTED PRIVATE KEY-----`),

		// Connection strings
		"connection_string": regexp.MustCompile(`(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp|mssql)://[^\s"']+@[^\s"']+`),
		"jdbc_string":       regexp.MustCompile(`jdbc:[a-z]+://[^\s"']+`),
		"dsn_string":        regexp.MustCompile(`(?i)(?:server|host)=[^;\s]+;.*(?:password|pwd)=[^;\s]+`),

		// API keys and tokens
		"github_token":      regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`),
		"github_classic":    regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`),
		"gitlab_token":      regexp.MustCompile(`glpat-[A-Za-z0-9\-]{20,}`),
		"slack_token":       regexp.MustCompile(`xox[bpars]-[0-9A-Za-z\-]+`),
		"slack_webhook":     regexp.MustCompile(`hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`),
		"stripe_key":        regexp.MustCompile(`(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}`),
		"twilio_key":        regexp.MustCompile(`SK[0-9a-f]{32}`),
		"sendgrid_key":      regexp.MustCompile(`SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`),
		"mailgun_key":       regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
		"npm_token":         regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
		"heroku_key":        regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		"azure_key":         regexp.MustCompile(`(?i)(?:DefaultEndpointsProtocol|AccountKey)=[^\s;]+`),

		// Kubernetes
		"k8s_token":         regexp.MustCompile(`eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9\.eyJpc3MiOiJrdWJlcm5ldGVz`),
		"k8s_secret":        regexp.MustCompile(`(?i)kubernetes\.io/service-account-token`),

		// Error messages (stack traces and debug info)
		"java_exception":    regexp.MustCompile(`java\.[a-z]+\.[A-Z]\w+Exception`),
		"java_stacktrace":   regexp.MustCompile(`at [a-z]+\.[a-z]+\.[A-Z]\w+\.\w+\([A-Z]\w+\.java:\d+\)`),
		"python_traceback":  regexp.MustCompile(`Traceback \(most recent call last\)`),
		"python_error":      regexp.MustCompile(`File "[^"]+\.py", line \d+`),
		"php_error":         regexp.MustCompile(`(?:Fatal error|Parse error|Warning):.*in .* on line \d+`),
		"php_stack":         regexp.MustCompile(`#\d+ (?:/[^\s]+\.php)\(\d+\):`),
		"dotnet_error":      regexp.MustCompile(`(?:System\.\w+Exception|Microsoft\.\w+\.\w+Exception)`),
		"dotnet_stack":      regexp.MustCompile(`at [A-Z]\w+\.\w+\.\w+\(.*\) in [^\s]+:\d+`),
		"ruby_error":        regexp.MustCompile(`(?:app|lib)/[^\s]+\.rb:\d+:in`),
		"go_panic":          regexp.MustCompile(`goroutine \d+ \[running\]:`),
		"node_error":        regexp.MustCompile(`at [A-Za-z]+\s+\([^\s]+\.js:\d+:\d+\)`),

		// SQL errors (database type disclosure)
		"sql_error":         regexp.MustCompile(`(?:SQL syntax.*MySQL|ORA-\d{5}|SQLSTATE\[\w+\]|pg_query\(\)|sqlite3\.OperationalError)`),
		"sql_error_mssql":   regexp.MustCompile(`(?:Microsoft SQL Server|SQL Server Error|mssql_query\(\))`),
		"sql_error_detail":  regexp.MustCompile(`(?i)(?:you have an error in your sql|near ".*" at line|syntax error at or near)`),

		// Directory/path disclosure
		"path_disclosure":   regexp.MustCompile(`(?:/home/\w+/|/var/www/|/opt/|/srv/|C:\\\\(?:Users|inetpub|Program Files)\\\\)`),

		// Passwords in plaintext
		"password_field":    regexp.MustCompile(`(?i)"(?:password|passwd|secret|api_key|apikey|access_token|private_key)"\s*:\s*"[^"]{8,}"`),

		// Internal IPs (non-RFC1918 exposure)
		"internal_ip":       regexp.MustCompile(`(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`),
	}

	for name, pattern := range patterns {
		if pattern.MatchString(body) {
			sensitive = append(sensitive, name)
		}
	}

	// Check response headers for sensitive data too
	for headerName, vals := range resp.Headers {
		hl := strings.ToLower(headerName)
		for _, v := range vals {
			// Server version disclosure in new headers
			if (hl == "server" || hl == "x-powered-by") && len(v) > 0 {
				// Only flag if it reveals specific version numbers
				if regexp.MustCompile(`\d+\.\d+`).MatchString(v) {
					sensitive = append(sensitive, "server_version:"+v)
					break
				}
			}
		}
	}

	return sensitive
}

func detectSensitiveDataDelta(baseline, mutated *ResponseContext, profile *BaselineProfile) []string {
	// Only report sensitive data that is NEW compared to baseline
	var baselineSensitive []string
	if profile != nil {
		baselineSensitive = profile.BaselineSensitive
	} else {
		baselineSensitive = detectSensitiveDataRaw(baseline)
	}

	mutatedSensitive := detectSensitiveDataRaw(mutated)

	baseSet := make(map[string]bool)
	for _, s := range baselineSensitive {
		baseSet[s] = true
	}

	var newSensitive []string
	for _, s := range mutatedSensitive {
		if !baseSet[s] {
			newSensitive = append(newSensitive, s)
		}
	}
	return newSensitive
}

// --- CORS Misconfiguration Detection (Strict) ---

func detectCORSMisconfigStrict(baseline, mutated *ResponseContext) (bool, string) {
	// Get CORS headers from mutated response
	allowOrigin := getHeaderValue(mutated.Headers, "access-control-allow-origin")
	allowCreds := strings.EqualFold(getHeaderValue(mutated.Headers, "access-control-allow-credentials"), "true")
	allowMethods := getHeaderValue(mutated.Headers, "access-control-allow-methods")
	allowHeaders := getHeaderValue(mutated.Headers, "access-control-allow-headers")

	if allowOrigin == "" {
		return false, ""
	}

	// Check if baseline already has this exact CORS config — if so, mutation didn't cause it
	baselineOrigin := getHeaderValue(baseline.Headers, "access-control-allow-origin")
	if baselineOrigin == allowOrigin {
		// Check if methods/headers were expanded by our mutation
		baselineMethods := getHeaderValue(baseline.Headers, "access-control-allow-methods")
		baselineHeaders := getHeaderValue(baseline.Headers, "access-control-allow-headers")

		// New methods added (e.g., PUT/DELETE/PATCH not in baseline)
		if allowMethods != baselineMethods && allowMethods != "" {
			dangerousMethods := []string{"PUT", "DELETE", "PATCH"}
			for _, dm := range dangerousMethods {
				if strings.Contains(strings.ToUpper(allowMethods), dm) && !strings.Contains(strings.ToUpper(baselineMethods), dm) {
					return true, "CORS method expansion: " + allowMethods
				}
			}
		}

		// New headers allowed (e.g., Authorization not in baseline)
		if allowHeaders != baselineHeaders && allowHeaders != "" {
			if strings.Contains(strings.ToLower(allowHeaders), "authorization") && !strings.Contains(strings.ToLower(baselineHeaders), "authorization") {
				return true, "CORS header expansion: Authorization now allowed"
			}
		}

		return false, ""
	}

	// Wildcard + credentials = Critical (but only if mutation caused it)
	if allowOrigin == "*" && allowCreds {
		return true, "CRITICAL: Wildcard origin with credentials allowed"
	}

	// Null origin reflected — only if we sent null origin
	if allowOrigin == "null" {
		return true, "Null origin reflected - exploitable via sandboxed iframe"
	}

	// Check if an attacker-controlled origin was reflected
	attackerDomains := []string{"evil.com", "attacker.com", "randomorigin123.com", "anything.goes.here"}
	for _, domain := range attackerDomains {
		if strings.Contains(allowOrigin, domain) {
			details := "Arbitrary origin reflected: " + allowOrigin
			if allowCreds {
				details = "CRITICAL: " + details + " WITH credentials"
			}
			return true, details
		}
	}

	// Wildcard without credentials — notable but lower severity
	if allowOrigin == "*" && baselineOrigin != "*" {
		return true, "Wildcard origin allows any site to read responses"
	}

	// Subdomain takeover risk: allowing *.example.com when we sent evil.example.com
	if strings.Contains(allowOrigin, ".") && allowCreds {
		// Check if the reflected origin is different from the target
		if allowOrigin != baselineOrigin && baselineOrigin == "" {
			return true, "Origin reflected with credentials: " + allowOrigin
		}
	}

	return false, ""
}

// --- Information Disclosure Detection (Strict) ---

func detectInfoDisclosureStrict(baseline, mutated *ResponseContext, profile *BaselineProfile) []string {
	var disclosures []string

	// Only flag NEW headers that reveal sensitive information
	// and were NOT present in baseline
	sensitiveInfoHeaders := map[string]bool{
		"server":                true,
		"x-powered-by":         true,
		"x-aspnet-version":     true,
		"x-aspnetmvc-version":  true,
		"x-debug-token":        true,
		"x-debug-token-link":   true,
		"x-backend-server":     true,
		"x-runtime":            true,
		"x-generator":          true,
		"x-php-version":        true,
		"x-drupal-cache":       true,
		"x-drupal-dynamic-cache": true,
		"x-django-debug":       true,
		"x-laravel-version":    true,
		"x-rails-version":      true,
		"x-symfony-version":    true,
		"x-debug-info":         true,
		"x-source-map":         true,
		"sourcemap":            true,
		"x-application-context": true,
		"x-environment":        true,
		"x-server-name":        true,
		"x-database-name":      true,
	}

	for k, vals := range mutated.Headers {
		if _, exists := baseline.Headers[k]; exists {
			continue
		}

		if profile != nil {
			if profile.ConsistentHeaders[strings.ToLower(k)] {
				continue
			}
		}

		kl := strings.ToLower(k)
		if sensitiveInfoHeaders[kl] && len(vals) > 0 && vals[0] != "" {
			disclosures = append(disclosures, k+": "+vals[0])
		}

		// Catch any header containing "version", "debug", or "internal" that's new
		if !sensitiveInfoHeaders[kl] && len(vals) > 0 && vals[0] != "" {
			if strings.Contains(kl, "version") || strings.Contains(kl, "debug") ||
				strings.Contains(kl, "internal") || strings.Contains(kl, "trace") {
				disclosures = append(disclosures, k+": "+vals[0])
			}
		}
	}

	// Check for new sensitive data patterns (only delta from baseline)
	newSensitive := detectSensitiveDataDelta(baseline, mutated, profile)
	for _, s := range newSensitive {
		disclosures = append(disclosures, "new_sensitive_data: "+s)
	}

	return disclosures
}

// --- Timing Anomaly Detection (Statistical) ---

func detectTimingAnomalyStrict(baseline, mutated *ResponseContext, profile *BaselineProfile) string {
	delta := mutated.TimingMS - baseline.TimingMS

	if profile != nil && profile.TimingStdDev > 0 {
		// Use statistical analysis: flag only if > 3 standard deviations
		zScore := float64(delta) / profile.TimingStdDev
		if zScore > 5.0 && delta > 5000 {
			return "critical_delay"
		}
		if zScore > 4.0 && delta > 3000 {
			return "significant_delay"
		}
		if zScore > 3.0 && delta > 2000 {
			return "moderate_delay"
		}
		// Require both statistical significance AND absolute threshold
		return ""
	}

	// Fallback: without profile, use conservative absolute thresholds only
	if delta > 10000 {
		return "critical_delay"
	}
	if delta > 5000 {
		return "significant_delay"
	}

	return ""
}

// --- IsSignificant with confidence weighting ---

func (d *DiffResult) IsSignificant() bool {
	// Auth bypass and privilege escalation are always significant (already validated strictly)
	if d.AuthBypass {
		return true
	}
	if d.PrivilegeElevate {
		return true
	}

	// AuthChallengeGone combined with status change is a strong auth bypass corroboration
	if d.AuthChallengeGone && d.StatusChanged {
		return true
	}

	// Location header changed — potential open redirect or cache poisoning
	// But only if it points to a different domain or contains attacker-controlled data
	if d.LocationChanged && d.LocationHeader != "" {
		loc := strings.ToLower(d.LocationHeader)
		// Redirect to external domain = open redirect
		if strings.Contains(loc, "evil.com") || strings.Contains(loc, "attacker.com") ||
			strings.Contains(loc, "javascript:") || strings.Contains(loc, "data:") {
			return true
		}
		// Redirect to different path than baseline = interesting
		if d.StatusChanged {
			return true
		}
		// Redirect containing injected header values = reflection in redirect
		return true
	}

	// CORS misconfiguration with actual reflection
	if d.CORSMisconfigured {
		return true
	}

	// Header reflection only if in dangerous context
	if d.HeaderReflection && d.ReflectedValue != "" {
		ctx := d.ReflectedValue
		if strings.Contains(ctx, "js_context") ||
			strings.Contains(ctx, "html_dangerous_attr") ||
			strings.Contains(ctx, "html_unescaped") ||
			strings.Contains(ctx, "header:exact") {
			return true
		}
		// "html_attr" without dangerous attrs, or "safe" — not significant
	}

	// New sensitive data (delta from baseline)
	if len(d.SensitiveDataFound) > 0 {
		return true
	}

	// Info disclosure of sensitive headers
	if len(d.InfoDisclosure) > 0 {
		return true
	}

	// Timing anomaly: ONLY significant if combined with other structural signal (Rule #2)
	// Timing alone is never enough — must be accompanied by status/body/header change
	if d.TimingAnomaly == "critical_delay" || d.TimingAnomaly == "significant_delay" {
		hasStructuralSignal := d.StatusChanged || d.BodyHashChanged ||
			len(d.HeadersAdded) > 0 || len(d.HeadersRemoved) > 0 ||
			d.HeaderReflection || d.ContentTypeChanged
		if hasStructuralSignal {
			return true
		}
		// Timing alone is flagged but handled as timing-only by orchestrator
		return true // let orchestrator decide display
	}

	// Status change only matters for meaningful transitions:
	// auth-denied → success (already caught by AuthBypass)
	// error → success with different content
	if d.StatusChanged {
		// Not significant on its own — too many false positives
		// Only significant if combined with other evidence
		evidenceCount := 0
		if len(d.NewJSONKeys) > 3 {
			evidenceCount++
		}
		if d.BodyHashChanged && math.Abs(d.SizeChangeRatio-1.0) > 0.5 {
			evidenceCount++
		}
		if evidenceCount > 0 {
			return true
		}
	}

	// New JSON keys only significant if there are many (>5) and combined with other changes
	if len(d.NewJSONKeys) > 5 && d.BodyHashChanged {
		return true
	}

	return false
}

// IsTimingOnly returns true if timing anomaly is the ONLY signal (Rule #2)
func (d *DiffResult) IsTimingOnly() bool {
	if d.TimingAnomaly == "" {
		return false
	}
	// If any structural signal exists alongside timing, it's not timing-only
	if d.StatusChanged || d.BodyHashChanged || d.HeaderReflection ||
		d.AuthBypass || d.PrivilegeElevate || d.CORSMisconfigured ||
		d.ContentTypeChanged || d.LocationChanged || d.AuthChallengeGone ||
		len(d.HeadersAdded) > 0 || len(d.HeadersRemoved) > 0 ||
		len(d.NewJSONKeys) > 0 || len(d.SensitiveDataFound) > 0 ||
		len(d.InfoDisclosure) > 0 {
		return false
	}
	return true
}

// IsCookieOnly returns true if new cookies are the ONLY difference
func (d *DiffResult) IsCookieOnly() bool {
	if len(d.SetCookieValues) == 0 {
		return false
	}
	// If any other signal exists, it's not cookie-only
	if d.StatusChanged || d.BodyHashChanged || d.HeaderReflection ||
		d.AuthBypass || d.PrivilegeElevate || d.CORSMisconfigured ||
		d.ContentTypeChanged || d.LocationChanged || d.AuthChallengeGone ||
		len(d.HeadersAdded) > 0 || len(d.HeadersRemoved) > 0 ||
		len(d.NewJSONKeys) > 0 || len(d.SensitiveDataFound) > 0 ||
		len(d.InfoDisclosure) > 0 || d.TimingAnomaly != "" {
		return false
	}
	return true
}

// --- Helper functions ---

func getHeaderValue(headers map[string][]string, name string) string {
	for k, vals := range headers {
		if strings.EqualFold(k, name) && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

func extractJSONKeys(body []byte) []string {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return []string{}
	}
	return extractKeysRecursive(data, "")
}

func extractKeysRecursive(data map[string]interface{}, prefix string) []string {
	keys := make([]string, 0)
	for k, v := range data {
		fullKey := k
		if prefix != "" {
			fullKey = prefix + "." + k
		}
		keys = append(keys, fullKey)
		if nested, ok := v.(map[string]interface{}); ok {
			keys = append(keys, extractKeysRecursive(nested, fullKey)...)
		}
	}
	return keys
}

func findNewKeys(baseline, mutated []string) []string {
	baselineMap := make(map[string]bool)
	for _, k := range baseline {
		baselineMap[k] = true
	}

	newKeys := []string{}
	for _, k := range mutated {
		if !baselineMap[k] {
			newKeys = append(newKeys, k)
		}
	}
	return newKeys
}

func findNewHeaders(baseline, mutated map[string][]string) []string {
	newHeaders := []string{}
	for k := range mutated {
		if _, exists := baseline[k]; !exists {
			newHeaders = append(newHeaders, k)
		}
	}
	return newHeaders
}

func findRemovedHeaders(baseline, mutated map[string][]string) []string {
	removed := []string{}
	for k := range baseline {
		if _, exists := mutated[k]; !exists {
			removed = append(removed, k)
		}
	}
	return removed
}

func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func stddev(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	m := mean(values)
	sum := 0.0
	for _, v := range values {
		diff := v - m
		sum += diff * diff
	}
	return math.Sqrt(sum / float64(len(values)-1))
}

// filterNonVolatile returns only headers NOT in the volatile set
func filterNonVolatile(headers []string, volatile map[string]bool) []string {
	var filtered []string
	for _, h := range headers {
		if !volatile[strings.ToLower(h)] {
			filtered = append(filtered, h)
		}
	}
	return filtered
}

// cookieNameFromSetCookie extracts the cookie name from a Set-Cookie value
func cookieNameFromSetCookie(sc string) string {
	idx := strings.Index(sc, "=")
	if idx <= 0 {
		return ""
	}
	return strings.TrimSpace(sc[:idx])
}
