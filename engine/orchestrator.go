package engine

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	GetAuthMutations        func() []Mutation
	GetProxyMutations       func() []Mutation
	GetCORSMutations        func() []Mutation
	GetCacheMutations       func() []Mutation
	GetOverrideMutations    func() []Mutation
	GetCloudMutations       func() []Mutation
	GetDebugMutations       func() []Mutation
	GetSmugglingMutations   func() []Mutation
	GetInjectionMutations   func() []Mutation
	GetSSRFMutations        func() []Mutation
	GetHopByHopMutations    func() []Mutation
	GetRateLimitMutations   func() []Mutation
	GetSecurityMutations    func() []Mutation
	GetWebSocketMutations   func() []Mutation
	GetJWTMutations         func() []Mutation
	GetCRLFMutations        func() []Mutation
	GetCookieMutations      func() []Mutation
	GetContentTypeMutations func() []Mutation
	GetRedirectMutations    func() []Mutation
	GetProtocolMutations    func() []Mutation
	GetEncodingMutations    func() []Mutation
	GetGatewayMutations     func() []Mutation
)

const (
	baselineSamples     = 5
	minConfidenceReport = 0.2 // let orchestrator logic handle display filtering
)

type ScanConfig struct {
	URL         string
	Method      string
	Headers     map[string]string
	Body        []byte
	ContentType string
	Auth        bool
	Proxy       bool
	CORS        bool
	Cache       bool
	Override    bool
	Cloud       bool
	Debug       bool
	Smuggling   bool
	Injection   bool
	SSRF        bool
	HopByHop    bool
	RateLimit   bool
	Security    bool
	WebSocket   bool
	JWT         bool
	CRLF        bool
	Cookie      bool
	ContentTypeCat bool
	Redirect    bool
	Protocol    bool
	Encoding    bool
	Gateway     bool
	Chain       bool
	DiffOnly    bool
	PrivCheck   bool
	WAFEvasion  bool
	Audit       bool
	Recon       bool
	Verify      bool
	ProxyURL    string
	Workers     int
	RateDelay   int
	Stealth     bool
	Timeout     time.Duration

	// v4.0 features
	OOBServer       *OOBServer
	OOBWait         time.Duration
	FollowRedirects bool
	MatchStatus     []int
	FilterStatus    []int
	MatchSize       int64
	FilterSize      int64

	// v0.2.2 false-positive elimination
	TimingOnly bool     // --timing-only: show timing-only findings
	ShowAll    bool     // --all: show LOW and timing-only findings
	Verbose    bool     // --verbose: show normalized diff for each finding
	ScopeRules []string // loaded from --scope file
}

type ScanResult struct {
	Findings      []Finding      `json:"findings"`
	SecurityAudit *SecurityAudit `json:"security_audit,omitempty"`
	Recon         *ReconSummary  `json:"recon,omitempty"`
	Stats         ScanStats      `json:"stats"`
	TargetURL     string         `json:"target_url"`
}

type ScanStats struct {
	TotalMutations   int           `json:"total_mutations"`
	TotalFindings    int           `json:"total_findings"`
	Critical         int           `json:"critical"`
	High             int           `json:"high"`
	Medium           int           `json:"medium"`
	Low              int           `json:"low"`
	Info             int           `json:"info"`
	Duration         time.Duration `json:"duration"`
	BaselineStatus   int           `json:"baseline_status"`
	BaselineSize     int64         `json:"baseline_size"`
	BaselineTime     int64         `json:"baseline_time_ms"`
	ReconRequests    int           `json:"recon_requests,omitempty"`
	VerifiedFindings int           `json:"verified_findings,omitempty"`
	OOBConfirmed     int           `json:"oob_confirmed,omitempty"`
	ChainsTested     int           `json:"chains_tested,omitempty"`
}

type Orchestrator struct {
	config           *ScanConfig
	client           *http.Client
	baseline         *ResponseContext
	profile          *BaselineProfile
	reconResult      *ReconResult
	techProfile      *TechProfile
	findings         []Finding
	verified         int
	confirmedHeaders map[string]bool // headers that showed signal from benign probes
	mu               sync.Mutex
	progress         int64 // atomic counter for progress display
	totalMuts        int64 // total mutations to test

	// Rejection-fingerprint clustering: detects WAF/CDN/proxy block pages that
	// collapse many distinct payloads into the same response shape.
	rejectionFingerprints map[responseFingerprint]bool
	fingerprintStats      map[responseFingerprint]*fingerprintStats
	fpMu                  sync.Mutex
	rejectionAnnounced    bool
}

func NewOrchestrator(config *ScanConfig) *Orchestrator {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}

	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	redirectPolicy := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if config.FollowRedirects {
		redirectPolicy = nil // Use default redirect policy
	}

	client := &http.Client{
		Transport:     transport,
		Timeout:       config.Timeout,
		CheckRedirect: redirectPolicy,
	}

	return &Orchestrator{
		config:                config,
		client:                client,
		findings:              []Finding{},
		confirmedHeaders:      make(map[string]bool),
		rejectionFingerprints: make(map[responseFingerprint]bool),
		fingerprintStats:      make(map[responseFingerprint]*fingerprintStats),
	}
}

func (o *Orchestrator) Scan() (*ScanResult, error) {
	startTime := time.Now()

	fmt.Printf("\033[0;34m[INFO]\033[0m Scanning target: \033[1m%s\033[0m\n", o.config.URL)

	// Establish baseline
	baselineCtx := NewRequestContext(o.config.URL, o.config.Method)
	for k, v := range o.config.Headers {
		baselineCtx.AddHeader(k, v)
	}
	if len(o.config.Body) > 0 {
		baselineCtx.SetBody(o.config.Body, o.config.ContentType)
	}

	fmt.Printf("\033[0;34m[INFO]\033[0m Establishing baseline (%d samples)...\n", baselineSamples)
	var baselineResponses []*ResponseContext
	for i := 0; i < baselineSamples; i++ {
		resp, err := baselineCtx.Execute(o.client)
		if err != nil {
			if i == 0 {
				return nil, fmt.Errorf("baseline request failed: %w", err)
			}
			break
		}
		baselineResponses = append(baselineResponses, resp)
		if i < baselineSamples-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	o.baseline = baselineResponses[0]
	o.profile = NewBaselineProfile(baselineResponses)

	fmt.Printf("\033[0;32m[+]\033[0m Baseline: %d (size: %d bytes, time: %dms)",
		o.baseline.StatusCode, len(o.baseline.Body), o.baseline.TimingMS)
	if !o.profile.StatusConsistent {
		fmt.Printf(" \033[0;33m[UNSTABLE STATUS]\033[0m")
	}
	if !o.profile.BodyConsistent {
		fmt.Printf(" \033[0;33m[DYNAMIC BODY]\033[0m")
	}
	if o.profile.TimingStdDev > 500 {
		fmt.Printf(" \033[0;33m[HIGH JITTER: %.0fms]\033[0m", o.profile.TimingStdDev)
	}
	fmt.Println()

	// WAF / CDN / proxy calibration: identify rejection fingerprints upfront
	// so collapsed block pages cannot be mistaken for findings.
	o.calibrateRejection()

	// Security Audit
	var audit *SecurityAudit
	if o.config.Audit {
		fmt.Println("\033[0;34m[INFO]\033[0m Running passive security audit...")
		audit = RunSecurityAudit(o.baseline)
		o.printAuditSummary(audit)

		// Build tech profile for adaptive scanning
		o.techProfile = BuildTechProfile(audit)
		if o.techProfile != nil {
			summary := GetAdaptiveSummary(o.techProfile)
			fmt.Printf("\033[0;36m[ADAPT]\033[0m %s\n", summary)
		}
	}

	// Reconnaissance phase
	if o.config.Recon {
		o.reconResult = RunRecon(o.client, o.config, o.baseline, o.profile)
		reconFindings := ReconToFindings(o.reconResult)
		for _, f := range reconFindings {
			if f.ConfidenceScore >= minConfidenceReport {
				o.addFinding(f)
			}
		}
	}

	// Generate mutations
	mutations := o.generateMutations()

	// Technology-adaptive prioritization
	if o.techProfile != nil {
		mutations = PrioritizeMutationsForTech(mutations, o.techProfile)
	}

	// Reflected header prioritization
	if o.reconResult != nil {
		mutations = o.prioritizeMutations(mutations)
	}

	// Inject OOB callback payloads
	if o.config.OOBServer != nil && o.config.OOBServer.IsRunning() {
		mutations = InjectOOBPayloads(o.config.OOBServer, mutations)
		fmt.Printf("\033[0;35m[OOB]\033[0m Injected OOB callback payloads (%d pending interactions)\n",
			o.config.OOBServer.PendingCount())
	}

	// Generate chain mutations
	chainsTested := 0
	if o.config.Chain {
		chains := GenerateChains(mutations, 3)
		chainMutations := ChainedToMutations(chains)
		chainsTested = len(chainMutations)
		mutations = append(mutations, chainMutations...)
		if chainsTested > 0 {
			fmt.Printf("\033[0;34m[CHAIN]\033[0m Generated %d chained mutation combinations\n", chainsTested)
		}
	}

	if o.config.Workers == 0 {
		o.config.Workers = 30
	}

	// Rule #5: Split mutations into benign (phase 1) and escalation (phase 2)
	var benignMutations, escalationMutations []Mutation
	for _, m := range mutations {
		if isEscalationPayload(m.Value) {
			escalationMutations = append(escalationMutations, m)
		} else {
			benignMutations = append(benignMutations, m)
		}
	}

	totalCount := len(benignMutations) + len(escalationMutations)
	fmt.Printf("\033[0;34m[INFO]\033[0m Generated \033[1m%d\033[0m mutations across %d categories",
		totalCount, o.countActiveCategories())
	if len(escalationMutations) > 0 {
		fmt.Printf(" (%d benign, %d escalation)", len(benignMutations), len(escalationMutations))
	}
	fmt.Println()

	// Phase 1: Run benign probes
	atomic.StoreInt64(&o.totalMuts, int64(totalCount))
	atomic.StoreInt64(&o.progress, 0)
	o.runMutationBatch(benignMutations)

	// Build confirmed header set from phase 1 findings + recon
	o.mu.Lock()
	for _, f := range o.findings {
		o.confirmedHeaders[strings.ToLower(f.Header)] = true
	}
	if o.reconResult != nil {
		for h := range o.reconResult.ReflectedHeaderSet() {
			o.confirmedHeaders[h] = true
		}
	}
	o.mu.Unlock()

	// Phase 2: Run escalation payloads only for confirmed headers
	if len(escalationMutations) > 0 {
		if len(o.confirmedHeaders) > 0 {
			var filtered []Mutation
			for _, m := range escalationMutations {
				if o.confirmedHeaders[strings.ToLower(m.Header)] {
					filtered = append(filtered, m)
				}
			}
			if len(filtered) > 0 {
				fmt.Printf("\033[0;33m[ESCALATE]\033[0m %d injection payloads for %d confirmed headers\n",
					len(filtered), len(o.confirmedHeaders))
				o.runMutationBatch(filtered)
			} else {
				skipped := len(escalationMutations)
				atomic.AddInt64(&o.progress, int64(skipped))
				fmt.Printf("\033[0;34m[SKIP]\033[0m %d escalation payloads — no confirmed headers match\n", skipped)
			}
		} else {
			skipped := len(escalationMutations)
			atomic.AddInt64(&o.progress, int64(skipped))
			fmt.Printf("\033[0;34m[SKIP]\033[0m %d escalation payloads — no reflection/signal detected\n", skipped)
		}
	}

	// OOB collection phase
	oobConfirmed := 0
	if o.config.OOBServer != nil && o.config.OOBServer.IsRunning() {
		waitDuration := o.config.OOBWait
		if waitDuration == 0 {
			waitDuration = 10 * time.Second
		}
		confirmed := o.config.OOBServer.CollectConfirmed(waitDuration)
		oobConfirmed = len(confirmed)
		if oobConfirmed > 0 {
			oobFindings := OOBToFindings(confirmed)
			for _, f := range oobFindings {
				o.addFinding(f)
			}
			fmt.Printf("\033[1;32m[OOB]\033[0m %d blind vulnerabilities confirmed via callback!\n", oobConfirmed)
		} else {
			fmt.Println("\033[0;34m[OOB]\033[0m No OOB callbacks received")
		}
	}

	// Filter findings that cannot be reproduced or are out of scope (Rule #9)
	o.mu.Lock()
	var filteredFindings []Finding
	for _, f := range o.findings {
		// Remove findings where new_cookies is the primary evidence
		if _, hasCookies := f.Evidence["new_cookies"]; hasCookies {
			evidenceCount := 0
			for k := range f.Evidence {
				if k != "new_cookies" && k != "timing_anomaly" && k != "timing_delta_ms" {
					evidenceCount++
				}
			}
			if evidenceCount == 0 {
				continue
			}
		}
		filteredFindings = append(filteredFindings, f)
	}
	o.findings = filteredFindings
	o.mu.Unlock()

	// Deduplicate findings
	o.mu.Lock()
	o.findings = DeduplicateFindings(o.findings)
	o.mu.Unlock()

	duration := time.Since(startTime)
	stats := o.calculateStats(len(mutations), duration)

	if o.reconResult != nil {
		stats.ReconRequests = o.reconResult.TotalRequests
	}
	stats.VerifiedFindings = o.verified
	stats.OOBConfirmed = oobConfirmed
	stats.ChainsTested = chainsTested

	fmt.Printf("\n\033[0;32m[DONE]\033[0m Scan complete in %s | %d mutations | %d findings",
		duration.Round(time.Millisecond), len(mutations), len(o.findings))
	if oobConfirmed > 0 {
		fmt.Printf(" | \033[1;32m%d OOB confirmed\033[0m", oobConfirmed)
	}
	fmt.Println()

	result := &ScanResult{
		Findings:      o.findings,
		SecurityAudit: audit,
		Stats:         stats,
		TargetURL:     o.config.URL,
	}

	if o.reconResult != nil {
		result.Recon = o.reconResult.ToSummary()
	}

	return result, nil
}

func (o *Orchestrator) testMutation(mutation Mutation, current, total int) {
	ctx := o.buildMutationRequest(mutation)

	resp, err := ctx.Execute(o.client)
	if err != nil {
		return
	}

	// Apply match/filter rules
	if !o.matchesFilters(resp) {
		return
	}

	// Discard responses representing server / WAF / CDN rejection rather than
	// application output. Combines: explicit 4xx/5xx rejection codes, known
	// WAF block-page body signatures, and fingerprint clustering.
	if o.isRejectionResponse(resp) {
		o.recordFingerprint(mutation, resp)
		return
	}

	// Track this response shape; if it matches a confirmed rejection cluster
	// we discard immediately even when the status alone wouldn't trigger.
	if o.recordFingerprint(mutation, resp) {
		o.announceRejectionPattern()
		return
	}

	diff := CalculateDiffWithProfile(o.baseline, resp, o.profile)

	reflected, reflectLocation := CheckHeaderReflection(mutation, resp, o.baseline)
	if reflected {
		diff.HeaderReflection = true
		diff.ReflectedValue = reflectLocation
	}

	// Use similarity engine for better false positive detection
	if diff.BodyHashChanged {
		sim := CalculateSimilarityWithProfile(o.baseline, resp, o.profile)
		// If normalized similarity is very high, the body change is just dynamic content
		if sim.NormalizedBodySimilarity > 0.95 && sim.StructuralSimilarity > 0.95 {
			diff.BodyHashChanged = false
		}
	}

	if o.config.DiffOnly && !diff.IsSignificant() {
		return
	}

	if diff.IsSignificant() {
		// Rule #4: Discard findings fully explained by volatile fields
		if isVolatileOnly(diff) {
			return
		}

		// Rule #9: Discard findings where new_cookies is the ONLY evidence
		if diff.IsCookieOnly() {
			return
		}

		// Rule #3: Content-Type injection validation
		if mutation.Category == "ContentType" {
			if !o.validateContentType(mutation, diff, resp) {
				return
			}
		}

		// Rule #4: Hop-by-hop structural validation
		if mutation.Category == "HopByHop" {
			if !o.validateHopByHop(diff) {
				return
			}
		}

		// Rule #5: Range header validation — applies to ALL categories when header is Range
		if isRangeHeader(mutation) {
			if !o.validateRange(mutation, resp) {
				return
			}
		}

		finding := o.createFinding(mutation, diff, resp)

		// Rule #2: Timing-only findings capped at 20% confidence
		if diff.IsTimingOnly() {
			finding.TimingOnly = true
			if finding.ConfidenceScore > 0.2 {
				finding.ConfidenceScore = 0.2
			}
			finding.Confidence = "Low"
			finding.Severity = "Info"
			finding.CVSS = 0.0
			// Skip unless --timing-only or --all
			if !o.config.TimingOnly && !o.config.ShowAll {
				return
			}
		}

		// Rule #7: Apply confidence threshold
		// Only show CONFIRMED (>=0.85) and HIGH (>=0.6) by default
		if !o.config.ShowAll && finding.ConfidenceScore < 0.6 {
			return
		}

		// Generate curl command (Rule #9)
		finding.CurlCommand = o.generateCurlCommand(mutation)

		// Rule #6: Scope filtering
		if len(o.config.ScopeRules) > 0 {
			if note := o.checkScope(finding); note != "" {
				finding.ScopeNote = note
			}
		}

		// Rule #3: Hop-by-hop auto-escalation to cache poisoning
		if mutation.Category == "HopByHop" {
			o.hopByHopEscalate(&finding)
		}

		// Rule #8: Enhanced verification with 3 retries
		if o.config.Verify && finding.ConfidenceScore >= 0.4 {
			verified, attempts := o.verifyFindingStrict(&finding, mutation)
			finding.VerifyAttempts = attempts
			if verified {
				finding.Reproducible = true
				o.mu.Lock()
				o.verified++
				o.mu.Unlock()
			} else if attempts >= 3 {
				// Failed 3 times → FALSE POSITIVE
				return
			}
		}

		o.printMutationResult(current, total, mutation, diff, resp)
		o.addFinding(finding)

		// Track confirmed headers for escalation phase
		o.mu.Lock()
		o.confirmedHeaders[strings.ToLower(mutation.Header)] = true
		o.mu.Unlock()
	}
}

// buildMutationRequest constructs a request context for a given mutation
func (o *Orchestrator) buildMutationRequest(mutation Mutation) *RequestContext {
	ctx := NewRequestContext(o.config.URL, o.config.Method)
	for k, v := range o.config.Headers {
		ctx.AddHeader(k, v)
	}
	if len(o.config.Body) > 0 {
		ctx.SetBody(o.config.Body, o.config.ContentType)
	}

	// Handle chained mutations (multi-header)
	if strings.Contains(mutation.Header, " + ") {
		pairs := strings.Split(mutation.Value, " | ")
		for _, pair := range pairs {
			colonIdx := strings.Index(pair, ": ")
			if colonIdx > 0 {
				hName := pair[:colonIdx]
				hVal := pair[colonIdx+2:]
				if o.config.WAFEvasion {
					hName = randomizeCase(hName)
				}
				ctx.AddHeader(hName, hVal)
			}
		}
	} else {
		headerName := mutation.Header
		headerValue := mutation.Value
		if o.config.WAFEvasion {
			headerName = randomizeCase(headerName)
		}
		ctx.AddHeader(headerName, headerValue)
	}
	return ctx
}

// validateContentType implements Rule #3: Content-Type injection validation
func (o *Orchestrator) validateContentType(mutation Mutation, diff *DiffResult, resp *ResponseContext) bool {
	// Signal A: injected value appears verbatim in response body AND was not
	// already present in the baseline (e.g. "text/javascript" in existing <script> tags)
	if strings.Contains(string(resp.Body), mutation.Value) &&
		!strings.Contains(string(o.baseline.Body), mutation.Value) {
		return true
	}
	// Signal B: response Content-Type header changed to match what we sent
	if diff.ContentTypeChanged {
		mutatedCT := getHeaderValue(resp.Headers, "content-type")
		if strings.Contains(mutatedCT, mutation.Value) {
			return true
		}
	}
	// Signal C: Vary header added AND body size delta >5% across 3 consistent runs
	varyHeader := getHeaderValue(resp.Headers, "vary")
	baselineVary := getHeaderValue(o.baseline.Headers, "vary")
	if varyHeader != baselineVary && varyHeader != "" {
		sizeRatio := diff.SizeChangeRatio
		if sizeRatio > 1.05 || sizeRatio < 0.95 {
			// Verify with 3 runs
			consistent := 0
			for i := 0; i < 3; i++ {
				ctx := o.buildMutationRequest(mutation)
				r, err := ctx.Execute(o.client)
				if err != nil {
					continue
				}
				v := getHeaderValue(r.Headers, "vary")
				if v != baselineVary && v != "" {
					consistent++
				}
			}
			if consistent >= 2 {
				return true // Signal C: suspected
			}
		}
	}
	return false
}

// validateHopByHop implements Rule #4: Hop-by-hop structural validation
func (o *Orchestrator) validateHopByHop(diff *DiffResult) bool {
	// Must show measurable structural difference after volatile normalization:
	// Content-Length changes by more than 10%
	if diff.SizeChangeRatio > 1.1 || diff.SizeChangeRatio < 0.9 {
		return true
	}
	// Content-Encoding appears or disappears
	for _, h := range diff.HeadersAdded {
		if strings.EqualFold(h, "content-encoding") {
			return true
		}
	}
	for _, h := range diff.HeadersRemoved {
		if strings.EqualFold(h, "content-encoding") {
			return true
		}
	}
	// A non-volatile security header appears or disappears
	securityHeaders := map[string]bool{
		"strict-transport-security": true, "content-security-policy": true,
		"x-frame-options": true, "x-content-type-options": true,
		"referrer-policy": true, "permissions-policy": true,
	}
	for _, h := range diff.HeadersAdded {
		if securityHeaders[strings.ToLower(h)] {
			return true
		}
	}
	for _, h := range diff.HeadersRemoved {
		if securityHeaders[strings.ToLower(h)] {
			return true
		}
	}
	// Status changed significantly
	if diff.StatusChanged {
		return true
	}
	// Header reflection
	if diff.HeaderReflection {
		return true
	}
	return false
}

// isRangeHeader checks if a mutation is a Range header test
func isRangeHeader(mutation Mutation) bool {
	return strings.EqualFold(mutation.Header, "Range")
}

// validateRange implements Rule #5: Range header validation.
// RFC 7233 multi-range support is normal server behavior. To be reportable,
// there must be evidence of a shared caching layer that could serve the
// partial response to other users (cache poisoning prerequisite).
func (o *Orchestrator) validateRange(mutation Mutation, resp *ResponseContext) bool {
	// Must change from 200 to 206 AND content-type to multipart/byteranges
	if o.baseline.StatusCode != 200 || resp.StatusCode != 206 {
		return false
	}
	ct := getHeaderValue(resp.Headers, "content-type")
	if !strings.Contains(strings.ToLower(ct), "multipart/byteranges") {
		return false
	}
	// Confirm with 3 runs
	consistent := 0
	for i := 0; i < 3; i++ {
		ctx := o.buildMutationRequest(mutation)
		r, err := ctx.Execute(o.client)
		if err != nil {
			continue
		}
		if r.StatusCode == 206 {
			rct := getHeaderValue(r.Headers, "content-type")
			if strings.Contains(strings.ToLower(rct), "multipart/byteranges") {
				consistent++
			}
		}
	}
	if consistent < 3 {
		return false
	}
	// Require evidence of a shared cache — without it, 206 is normal RFC 7233
	// behavior and there is no exploitable cache-poisoning vector.
	return hasCachingIndicators(resp)
}

// hasCachingIndicators returns true when response headers indicate a shared
// caching layer is present between the client and origin.
func hasCachingIndicators(resp *ResponseContext) bool {
	cacheHeaders := []string{
		"age", "x-cache", "x-cache-hits", "cf-cache-status",
		"x-varnish", "x-served-by", "x-fastly-request-id",
		"x-cache-lookup", "x-drupal-cache", "x-proxy-cache",
	}
	for _, h := range cacheHeaders {
		if v := getHeaderValue(resp.Headers, h); v != "" {
			return true
		}
	}
	// "Via" header with a proxy identifier also signals a cache
	via := getHeaderValue(resp.Headers, "via")
	if via != "" {
		return true
	}
	return false
}

// isServerRejection returns true when a probe response represents the server,
// proxy, CDN, or WAF explicitly rejecting the request rather than processing
// the injected header. These are never exploitable and must be discarded.
//
// From a 2xx baseline, any of these status codes mean the request was rejected
// at the perimeter, not that the application processed our payload:
//   - 4xx codes the application could not have produced from the same path
//     (the baseline already proved the path returns 2xx for normal traffic).
//   - 5xx codes from upstream gateways/CDNs indicating infrastructure failure.
func isServerRejection(baselineStatus, probeStatus int) bool {
	if baselineStatus < 200 || baselineStatus >= 300 {
		return false
	}
	switch probeStatus {
	case 400, // Bad Request — server could not parse the header
		403,  // Forbidden — WAF/policy block (Cloudflare, Imperva, AWS WAF, etc.)
		405,  // Method Not Allowed — Aliyun/CDN block response
		406,  // Not Acceptable — content negotiation rejection
		411,  // Length Required
		412,  // Precondition Failed
		413,  // Payload Too Large — header size rejection
		414,  // URI Too Long
		415,  // Unsupported Media Type
		417,  // Expectation Failed — Expect header rejected per RFC 7231
		418,  // I'm a teapot (some WAFs use this)
		421,  // Misdirected Request
		425,  // Too Early
		428,  // Precondition Required
		429,  // Too Many Requests — rate limit
		431,  // Request Header Fields Too Large
		451,  // Unavailable For Legal Reasons — geo/policy block
		494,  // Request Header Too Large (nginx)
		495,  // SSL Certificate Error (nginx)
		496,  // SSL Certificate Required (nginx)
		497,  // HTTP Request Sent to HTTPS Port (nginx)
		499,  // Client Closed Request (nginx)
		501,  // Not Implemented — method/feature rejected
		502,  // Bad Gateway — upstream rejected request
		503,  // Service Unavailable — overload / WAF block
		504,  // Gateway Timeout
		520, 521, 522, 523, 524, 525, 526, 527, 530: // Cloudflare custom errors
		return true
	}
	return false
}

// looksLikeWAFBlockPage returns true if the response body or headers contain
// signatures of a known WAF / CDN / proxy block page. These are returned by
// the perimeter, not the application, and never represent exploitation.
func looksLikeWAFBlockPage(resp *ResponseContext) bool {
	if resp == nil {
		return false
	}
	// Only treat as a block when the status indicates rejection. A 200 response
	// containing the word "blocked" in normal application copy must not match.
	if resp.StatusCode > 0 && resp.StatusCode < 400 {
		return false
	}
	body := strings.ToLower(string(resp.Body))
	if len(body) > 0 {
		signatures := []string{
			"your request has been blocked",
			"request has been blocked",
			"the request has been blocked",
			"您的访问被阻断",
			"由于您访问的url有可能对网站造成安全威胁",
			"sorry, your request has been blocked",
			"may cause potential threats to the server",
			"potential threats to the server's security",
			"the requested url was rejected",
			"please consult with your administrator",
			"support id:",
			"access denied",
			"attention required",
			"cloudflare ray id",
			"cf-browser-verification",
			"<awswafaction>",
			"aws waf",
			"incapsula incident id",
			"_incap_",
			"akamai reference",
			"reference&#32;&#35;",
			"errors.aliyun.com",
			"modsecurity",
			"mod_security",
			"sucuri website firewall",
			"barracuda",
			"fortiweb",
			"denyall",
			"conditionblocked",
			"blocked by waf",
			"your ip has been blocked",
			"your request looks similar to malicious",
			"this request has been blocked",
			"web application firewall",
			"the page you are looking for is temporarily unavailable",
			"requested url could not be retrieved",
		}
		for _, sig := range signatures {
			if strings.Contains(body, sig) {
				return true
			}
		}
	}
	for k := range resp.Headers {
		kl := strings.ToLower(k)
		if strings.Contains(kl, "waf") || strings.Contains(kl, "firewall") ||
			strings.Contains(kl, "blocked") || strings.Contains(kl, "incapsula") ||
			strings.Contains(kl, "x-sucuri") || strings.Contains(kl, "x-iinfo") {
			return true
		}
	}
	return false
}

// responseFingerprint identifies near-duplicate response shapes across probes.
// When many distinct payloads collapse to the same fingerprint, the perimeter
// is returning a generic block page instead of letting the application respond.
type responseFingerprint struct {
	Status     int
	SizeBucket int // body length in 256-byte buckets
}

func makeFingerprint(resp *ResponseContext) responseFingerprint {
	return responseFingerprint{
		Status:     resp.StatusCode,
		SizeBucket: len(resp.Body) / 256,
	}
}

type fingerprintStats struct {
	Count      int
	Categories map[string]bool
	Headers    map[string]bool
}

// recordFingerprint tracks a probe response shape and promotes it to a
// confirmed rejection pattern once the same shape appears for many distinct
// mutations across multiple categories or unique headers. Returns true when
// the response matches a confirmed rejection pattern.
func (o *Orchestrator) recordFingerprint(mutation Mutation, resp *ResponseContext) bool {
	if resp == nil {
		return false
	}
	// Responses that match the baseline status with comparable body size are
	// not rejection candidates and would only pollute the fingerprint table.
	if resp.StatusCode == o.baseline.StatusCode {
		baseSize := len(o.baseline.Body)
		if baseSize > 0 {
			ratio := float64(len(resp.Body)) / float64(baseSize)
			if ratio > 0.7 && ratio < 1.3 {
				return false
			}
		}
	}

	fp := makeFingerprint(resp)

	o.fpMu.Lock()
	defer o.fpMu.Unlock()

	if o.rejectionFingerprints[fp] {
		return true
	}

	stats, ok := o.fingerprintStats[fp]
	if !ok {
		stats = &fingerprintStats{
			Categories: make(map[string]bool),
			Headers:    make(map[string]bool),
		}
		o.fingerprintStats[fp] = stats
	}
	stats.Count++
	stats.Categories[mutation.Category] = true
	stats.Headers[strings.ToLower(mutation.Header)] = true

	// Promote to confirmed rejection when ≥5 hits and the cluster spans
	// either ≥2 attack categories or ≥3 distinct header names — strong
	// evidence the perimeter is collapsing distinct payloads to one page.
	if stats.Count >= 5 && (len(stats.Categories) >= 2 || len(stats.Headers) >= 3) {
		o.rejectionFingerprints[fp] = true
		return true
	}
	return false
}

// announceRejectionPattern emits a one-time notice that the perimeter is
// returning a generic block page for many distinct payloads. Helpful so the
// operator understands why the finding count drops to zero.
func (o *Orchestrator) announceRejectionPattern() {
	o.fpMu.Lock()
	already := o.rejectionAnnounced
	o.rejectionAnnounced = true
	o.fpMu.Unlock()
	if already {
		return
	}
	fmt.Println("\033[0;33m[BLOCK]\033[0m Perimeter is collapsing distinct payloads to a single block page — discarding matched responses as WAF rejections")
}

// calibrateRejection sends deliberately egregious probes against a few
// distinct headers and records the response fingerprints. Anything matching
// these fingerprints during the main scan is treated as a WAF/CDN rejection.
func (o *Orchestrator) calibrateRejection() {
	probes := []Mutation{
		{Header: "X-Calibration-Probe-1", Value: "<script>alert(1)</script>", Category: "_calibration"},
		{Header: "X-Calibration-Probe-2", Value: "${jndi:ldap://example.invalid/a}", Category: "_calibration"},
		{Header: "X-Calibration-Probe-3", Value: "' OR '1'='1' --", Category: "_calibration"},
		{Header: "X-Calibration-Probe-4", Value: "../../../../etc/passwd", Category: "_calibration"},
	}
	hits := 0
	for _, m := range probes {
		ctx := o.buildMutationRequest(m)
		resp, err := ctx.Execute(o.client)
		if err != nil || resp == nil {
			continue
		}
		if isServerRejection(o.baseline.StatusCode, resp.StatusCode) || looksLikeWAFBlockPage(resp) {
			fp := makeFingerprint(resp)
			o.fpMu.Lock()
			o.rejectionFingerprints[fp] = true
			o.fpMu.Unlock()
			hits++
		}
	}
	if hits > 0 {
		fmt.Printf("\033[0;33m[CALIBRATE]\033[0m Perimeter rejects egregious payloads (%d/%d probes) — block-page fingerprint locked in\n", hits, len(probes))
	}
}

// isRejectionResponse returns true when a probe response is server/WAF
// rejection rather than application output. Combines status-based detection,
// body signature detection, and fingerprint clustering.
func (o *Orchestrator) isRejectionResponse(resp *ResponseContext) bool {
	if isServerRejection(o.baseline.StatusCode, resp.StatusCode) {
		return true
	}
	if looksLikeWAFBlockPage(resp) {
		return true
	}
	fp := makeFingerprint(resp)
	o.fpMu.Lock()
	confirmed := o.rejectionFingerprints[fp]
	o.fpMu.Unlock()
	return confirmed
}

// generateCurlCommand builds a reproducible curl command for a finding (Rule #9)
func (o *Orchestrator) generateCurlCommand(mutation Mutation) string {
	parts := []string{"curl", "-sk"}
	if o.config.Method != "GET" {
		parts = append(parts, "-X", o.config.Method)
	}

	// Add custom headers
	for k, v := range o.config.Headers {
		parts = append(parts, "-H", fmt.Sprintf("'%s: %s'", k, v))
	}

	// Add mutation header(s)
	if strings.Contains(mutation.Header, " + ") {
		pairs := strings.Split(mutation.Value, " | ")
		for _, pair := range pairs {
			colonIdx := strings.Index(pair, ": ")
			if colonIdx > 0 {
				parts = append(parts, "-H", fmt.Sprintf("'%s'", pair))
			}
		}
	} else {
		parts = append(parts, "-H", fmt.Sprintf("'%s: %s'", mutation.Header, mutation.Value))
	}

	// Add body
	if len(o.config.Body) > 0 {
		parts = append(parts, "-d", fmt.Sprintf("'%s'", string(o.config.Body)))
	}

	parts = append(parts, fmt.Sprintf("'%s'", o.config.URL))
	return strings.Join(parts, " ")
}

// checkScope checks if a finding matches out-of-scope rules (Rule #6)
func (o *Orchestrator) checkScope(finding Finding) string {
	impactLower := strings.ToLower(finding.Impact)
	categoryLower := strings.ToLower(finding.Category)

	for _, rule := range o.config.ScopeRules {
		ruleLower := strings.ToLower(strings.TrimSpace(rule))
		if ruleLower == "" || strings.HasPrefix(ruleLower, "#") {
			continue
		}

		// Common out-of-scope categories
		if strings.Contains(ruleLower, "missing security header") || strings.Contains(ruleLower, "missing header") {
			if categoryLower == "security" && strings.Contains(impactLower, "missing") {
				return "Out of scope: missing security headers"
			}
		}
		if strings.Contains(ruleLower, "rate limit") {
			if categoryLower == "ratelimit" {
				return "Out of scope: rate limiting"
			}
		}
		if strings.Contains(ruleLower, "clickjack") {
			if strings.Contains(impactLower, "clickjack") || strings.Contains(impactLower, "x-frame") {
				return "Out of scope: clickjacking"
			}
		}
		if strings.Contains(ruleLower, "best practice") {
			if finding.Severity == "Info" || finding.Severity == "Low" {
				if !finding.Verified && finding.ConfidenceScore < 0.6 {
					return "Out of scope: best practice violation"
				}
			}
		}
		// Generic pattern match
		if strings.Contains(impactLower, ruleLower) || strings.Contains(categoryLower, ruleLower) {
			return "Out of scope: matches rule '" + rule + "'"
		}
	}
	return ""
}

// runMutationBatch executes a batch of mutations concurrently
func (o *Orchestrator) runMutationBatch(mutations []Mutation) {
	sem := make(chan struct{}, o.config.Workers)
	var wg sync.WaitGroup
	total := int(atomic.LoadInt64(&o.totalMuts))

	for i, mutation := range mutations {
		wg.Add(1)
		sem <- struct{}{}

		go func(idx int, mut Mutation) {
			defer wg.Done()
			defer func() { <-sem }()

			delay := o.config.RateDelay
			if o.config.Stealth {
				delay = maxInt(delay, 500)
			}
			if delay > 0 {
				time.Sleep(time.Duration(delay) * time.Millisecond)
			}

			current := int(atomic.AddInt64(&o.progress, 1))
			o.testMutation(mut, current, total)
		}(i, mutation)
	}

	wg.Wait()
}

// isEscalationPayload returns true for injection payloads that should only
// be sent after a benign probe confirms the header is interesting (Rule #5)
func isEscalationPayload(value string) bool {
	lower := strings.ToLower(value)
	markers := []string{
		// XSS
		"<script", "<img ", "<svg", "<iframe", "<object", "<embed",
		"onerror=", "onload=", "onfocus=", "onmouseover=",
		"javascript:", "\"alert(", "'alert(",
		// SSTI
		"${jndi:", "${{", "{{7*7}}", "#{7*7}",
		"${7*7}", "{{config", "{{self",
		// CRLF
		"%0d%0a", "%0D%0A",
		// SQLi
		"' or ", "\" or ", "1=1", "union select", "union+select",
		"' and ", "\" and ", "sleep(", "waitfor delay",
		// Command injection
		";cat ", "|cat ", "`cat ", "$(cat",
		";whoami", "|whoami", "`whoami", "$(whoami",
	}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	// Check for literal CRLF bytes
	if strings.ContainsAny(value, "\r\n") {
		return true
	}
	return false
}

// matchesFilters checks if a response matches the configured match/filter rules
func (o *Orchestrator) matchesFilters(resp *ResponseContext) bool {
	// Match status: if set, ONLY process these status codes
	if len(o.config.MatchStatus) > 0 {
		matched := false
		for _, s := range o.config.MatchStatus {
			if resp.StatusCode == s {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Filter status: exclude these status codes
	if len(o.config.FilterStatus) > 0 {
		for _, s := range o.config.FilterStatus {
			if resp.StatusCode == s {
				return false
			}
		}
	}

	// Match size: only process responses of this size (with 10% tolerance)
	if o.config.MatchSize > 0 {
		tolerance := float64(o.config.MatchSize) * 0.1
		size := float64(resp.ContentLength)
		if size < float64(o.config.MatchSize)-tolerance || size > float64(o.config.MatchSize)+tolerance {
			return false
		}
	}

	// Filter size: exclude responses of this size (with 10% tolerance)
	if o.config.FilterSize > 0 {
		tolerance := float64(o.config.FilterSize) * 0.1
		size := float64(resp.ContentLength)
		if size >= float64(o.config.FilterSize)-tolerance && size <= float64(o.config.FilterSize)+tolerance {
			return false
		}
	}

	return true
}

// isVolatileOnly returns true if all differences are fully explained by
// volatile fields — these findings should be silently discarded (Rule #4)
func isVolatileOnly(diff *DiffResult) bool {
	// Real security signals are never volatile
	if diff.AuthBypass || diff.PrivilegeElevate || diff.CORSMisconfigured ||
		diff.HeaderReflection || len(diff.SensitiveDataFound) > 0 {
		return false
	}
	if diff.StatusChanged {
		return false
	}
	if diff.LocationChanged {
		return false
	}
	if diff.AuthChallengeGone {
		return false
	}

	// After volatile filtering, if no meaningful header/cookie/body/info
	// changes remain, the diff is volatile-only
	if len(diff.HeadersAdded) == 0 && len(diff.HeadersRemoved) == 0 &&
		len(diff.SetCookieValues) == 0 && len(diff.NewJSONKeys) == 0 &&
		len(diff.InfoDisclosure) == 0 && !diff.ContentTypeChanged &&
		diff.TimingAnomaly == "" {
		return true
	}

	return false
}

// hopByHopEscalate sends a clean follow-up request to check if a hop-by-hop
// finding persists (indicating cache poisoning). Escalates to Critical if so (Rule #3).
func (o *Orchestrator) hopByHopEscalate(finding *Finding) {
	cleanCtx := NewRequestContext(o.config.URL, o.config.Method)
	for k, v := range o.config.Headers {
		cleanCtx.AddHeader(k, v)
	}
	if len(o.config.Body) > 0 {
		cleanCtx.SetBody(o.config.Body, o.config.ContentType)
	}

	cleanResp, err := cleanCtx.Execute(o.client)
	if err != nil {
		return
	}

	cleanDiff := CalculateDiffWithProfile(o.baseline, cleanResp, o.profile)
	if cleanDiff.IsSignificant() && !isVolatileOnly(cleanDiff) {
		// Delta persists without mutation → cache poisoning!
		finding.Severity = "Critical"
		finding.CVSS = 9.1
		finding.CWE = "CWE-525"
		finding.ConfidenceScore = 0.9
		finding.Confidence = "Confirmed"
		finding.Impact = "Cache Poisoning via " + finding.Impact
		finding.Evidence["cache_poisoning"] = "CONFIRMED: response delta persists on clean request"
	}
}

func (o *Orchestrator) printMutationResult(current, total int, mutation Mutation, diff *DiffResult, resp *ResponseContext) {
	progress := atomic.LoadInt64(&o.progress)
	totalMuts := atomic.LoadInt64(&o.totalMuts)

	pct := float64(progress) / float64(totalMuts) * 100
	if totalMuts == 0 {
		pct = 0
	}

	fmt.Printf("\033[0;33m[%d/%d %.0f%%]\033[0m %s: %s -> ", current, total, pct,
		mutation.Header, truncate(mutation.Value, 50))

	if diff.StatusChanged {
		fmt.Printf("\033[1;31m%d->%d\033[0m ", o.baseline.StatusCode, resp.StatusCode)
	}
	if diff.AuthBypass {
		fmt.Print("\033[1;31mAUTH_BYPASS\033[0m ")
	}
	if diff.PrivilegeElevate {
		fmt.Print("\033[1;31mPRIV_ELEVATE\033[0m ")
	}
	if diff.HeaderReflection {
		fmt.Printf("\033[1;35mREFLECTED(%s)\033[0m ", diff.ReflectedValue)
	}
	if diff.CORSMisconfigured {
		fmt.Print("\033[1;33mCORS_MISCONFIG\033[0m ")
	}
	if len(diff.NewJSONKeys) > 0 {
		fmt.Printf("\033[1;36mNEW_KEYS:%d\033[0m ", len(diff.NewJSONKeys))
	}
	if len(diff.SensitiveDataFound) > 0 {
		fmt.Printf("\033[1;31mSENSITIVE_DATA:%d\033[0m ", len(diff.SensitiveDataFound))
	}
	if len(diff.InfoDisclosure) > 0 {
		fmt.Printf("\033[1;33mINFO_LEAK:%d\033[0m ", len(diff.InfoDisclosure))
	}
	if diff.LocationChanged {
		fmt.Printf("\033[1;33mLOCATION_CHANGED\033[0m ")
	}
	if diff.AuthChallengeGone {
		fmt.Printf("\033[1;31mAUTH_CHALLENGE_GONE\033[0m ")
	}
	if diff.TimingAnomaly != "" {
		fmt.Printf("\033[1;33mTIMING:%s\033[0m ", diff.TimingAnomaly)
	}
	fmt.Println()
}

func (o *Orchestrator) createFinding(mutation Mutation, diff *DiffResult, resp *ResponseContext) Finding {
	evidence := make(map[string]string)

	if diff.StatusChanged {
		evidence["status_change"] = fmt.Sprintf("%d -> %d", o.baseline.StatusCode, resp.StatusCode)
	}
	if diff.AuthBypass {
		evidence["auth_bypass"] = "true"
	}
	if diff.PrivilegeElevate {
		evidence["privilege_elevation"] = "true"
	}
	if len(diff.NewJSONKeys) > 0 {
		evidence["new_json_keys"] = fmt.Sprintf("%v", diff.NewJSONKeys)
	}
	if diff.BodyHashChanged {
		evidence["body_hash_changed"] = "true"
		evidence["size_change"] = fmt.Sprintf("%.1f%%", (diff.SizeChangeRatio-1.0)*100)
	}
	if len(diff.HeadersAdded) > 0 {
		evidence["headers_added"] = fmt.Sprintf("%v", diff.HeadersAdded)
	}
	if len(diff.HeadersRemoved) > 0 {
		evidence["headers_removed"] = fmt.Sprintf("%v", diff.HeadersRemoved)
	}
	if diff.HeaderReflection {
		evidence["header_reflected"] = diff.ReflectedValue
	}
	if diff.CORSMisconfigured {
		evidence["cors_misconfigured"] = diff.CORSDetails
	}
	if len(diff.SensitiveDataFound) > 0 {
		evidence["sensitive_data"] = strings.Join(diff.SensitiveDataFound, ", ")
	}
	if len(diff.InfoDisclosure) > 0 {
		evidence["info_disclosure"] = strings.Join(diff.InfoDisclosure, "; ")
	}
	if diff.TimingAnomaly != "" {
		evidence["timing_anomaly"] = diff.TimingAnomaly
		evidence["timing_delta_ms"] = fmt.Sprintf("%d", diff.TimingDeltaMS)
	}
	if diff.LocationChanged {
		evidence["location_changed"] = diff.LocationHeader
	}
	if len(diff.SetCookieValues) > 0 {
		evidence["new_cookies"] = strings.Join(diff.SetCookieValues, "; ")
	}
	if diff.ContentTypeChanged {
		evidence["content_type_changed"] = "true"
	}
	if diff.AuthChallengeGone {
		evidence["auth_challenge_gone"] = "true"
	}

	severity, cvss, cwe, confidence := calculateSeverityStrict(mutation, diff, o.baseline, resp, o.profile)

	// Rule #7: Evidence-based confidence labeling
	if diff.HeaderReflection && strings.Contains(diff.ReflectedValue, "body:") {
		// Literal reflection in body → always CONFIRMED
		if confidence < 0.85 {
			confidence = 0.85
		}
	} else if diff.ContentTypeChanged {
		// Response Content-Type hijacked → CONFIRMED
		if confidence < 0.85 {
			confidence = 0.85
		}
	}
	confidenceLabel := confidenceLabelV2(confidence)

	remediation := getRemediation(mutation.Category, diff)

	return Finding{
		Header:          mutation.Header,
		Payload:         mutation.Value,
		Impact:          mutation.Impact,
		Confidence:      confidenceLabel,
		ConfidenceScore: confidence,
		Evidence:        evidence,
		Category:        mutation.Category,
		Severity:        severity,
		CVSS:            cvss,
		CWE:             cwe,
		Remediation:     remediation,
		Timestamp:       time.Now(),
	}
}

func calculateSeverityStrict(mutation Mutation, diff *DiffResult, baseline, resp *ResponseContext, profile *BaselineProfile) (string, float64, string, float64) {
	if diff.AuthBypass {
		confidence := 0.7
		if baseline.StatusCode == 401 && resp.StatusCode == 200 {
			confidence = 0.85
		}
		if baseline.StatusCode == 403 && resp.StatusCode == 200 {
			confidence = 0.8
		}
		if diff.SizeChangeRatio > 2.0 || diff.SizeChangeRatio < 0.5 {
			confidence += 0.1
		}
		if len(diff.NewJSONKeys) > 3 {
			confidence += 0.05
		}
		if diff.AuthChallengeGone {
			confidence += 0.1
		}
		if confidence > 1.0 {
			confidence = 1.0
		}
		return "Critical", 9.8, "CWE-287", confidence
	}

	if diff.AuthChallengeGone && diff.StatusChanged {
		confidence := 0.6
		if baseline.StatusCode == 401 && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			confidence = 0.75
		}
		return "High", 8.0, "CWE-287", confidence
	}

	if diff.PrivilegeElevate {
		confidence := 0.65
		if diff.StatusChanged {
			confidence += 0.1
		}
		if len(diff.NewJSONKeys) > 3 {
			confidence += 0.1
		}
		if confidence > 1.0 {
			confidence = 1.0
		}
		return "Critical", 8.8, "CWE-269", confidence
	}

	if diff.CORSMisconfigured {
		if strings.Contains(diff.CORSDetails, "CRITICAL") {
			return "Critical", 9.1, "CWE-942", 0.9
		}
		if strings.Contains(diff.CORSDetails, "Null origin") {
			return "High", 8.0, "CWE-942", 0.85
		}
		if strings.Contains(diff.CORSDetails, "Arbitrary origin") {
			return "High", 8.0, "CWE-942", 0.9
		}
		return "Medium", 6.5, "CWE-942", 0.7
	}

	if diff.HeaderReflection {
		ctx := diff.ReflectedValue
		if strings.Contains(ctx, "js_context") {
			confidence := 0.8
			if strings.Contains(mutation.Value, "<script") {
				confidence = 0.9
			}
			return "High", 7.5, "CWE-79", confidence
		}
		if strings.Contains(ctx, "html_dangerous_attr") {
			return "High", 7.5, "CWE-79", 0.75
		}
		if strings.Contains(ctx, "html_unescaped") {
			confidence := 0.6
			if strings.ContainsAny(mutation.Value, "<>") {
				confidence = 0.75
			}
			return "Medium", 6.1, "CWE-79", confidence
		}
		if strings.Contains(ctx, "header:exact") {
			return "Medium", 5.3, "CWE-116", 0.6
		}
		return "Low", 3.7, "CWE-116", 0.4
	}

	if len(diff.SensitiveDataFound) > 0 {
		for _, s := range diff.SensitiveDataFound {
			if s == "aws_key" || s == "private_key" || s == "connection_string" {
				return "Critical", 9.0, "CWE-200", 0.85
			}
		}
		return "Medium", 5.3, "CWE-200", 0.6
	}

	if len(diff.InfoDisclosure) > 0 {
		for _, d := range diff.InfoDisclosure {
			if strings.Contains(strings.ToLower(d), "debug") {
				return "Medium", 5.3, "CWE-200", 0.6
			}
		}
		return "Low", 3.7, "CWE-200", 0.5
	}

	if diff.TimingAnomaly != "" {
		if diff.TimingAnomaly == "critical_delay" {
			return "Medium", 5.3, "CWE-208", 0.5
		}
		return "Low", 3.7, "CWE-208", 0.4
	}

	if diff.StatusChanged {
		confidence := 0.3
		if baseline.StatusCode >= 400 && resp.StatusCode < 400 {
			confidence = 0.5
			if len(diff.NewJSONKeys) > 3 {
				confidence += 0.15
			}
			return "Medium", 5.3, "CWE-284", confidence
		}
		return "Low", 3.7, "CWE-16", confidence
	}

	return "Info", 0.0, "", 0.2
}

func getRemediation(category string, diff *DiffResult) string {
	if diff.AuthBypass {
		return "Ensure authentication is enforced server-side. Do not trust client-supplied headers for auth decisions. Validate tokens cryptographically."
	}
	if diff.PrivilegeElevate {
		return "Implement proper RBAC. Never trust client-supplied role/privilege headers. Enforce authorization checks on every request."
	}
	if diff.CORSMisconfigured {
		return "Restrict Access-Control-Allow-Origin to trusted domains. Never use wildcard with credentials. Validate Origin header server-side."
	}
	if diff.HeaderReflection {
		return "Never reflect user-supplied header values in responses without proper encoding. Implement output encoding and CSP headers."
	}

	remediations := map[string]string{
		"Auth":      "Validate all authentication server-side. Do not trust X-headers for auth. Use cryptographic token validation.",
		"Proxy":     "Strip or ignore untrusted proxy headers (X-Forwarded-For, X-Real-IP). Configure reverse proxy to set trusted headers.",
		"CORS":      "Implement strict origin validation. Use allowlist of trusted origins. Never reflect arbitrary origins.",
		"Cache":     "Include security-relevant headers in cache keys. Set appropriate Cache-Control headers. Use Vary header correctly.",
		"Override":  "Disable HTTP method override headers in production. Validate request methods server-side.",
		"Cloud":     "Ensure cloud provider headers are stripped at edge. Do not trust client-supplied cloud metadata headers.",
		"Debug":     "Disable debug mode in production. Remove debug headers. Use environment variables for configuration.",
		"Smuggling": "Normalize Transfer-Encoding handling. Reject ambiguous requests. Use HTTP/2 end-to-end.",
		"Injection": "Sanitize all header values. Implement WAF rules. Use Content-Security-Policy. Encode output.",
		"SSRF":      "Validate and sanitize all URL inputs. Block requests to internal IPs and metadata endpoints. Use allowlists.",
		"HopByHop":  "Strip hop-by-hop headers at proxy boundaries. Do not use Connection header to strip security-critical headers.",
		"RateLimit": "Implement rate limiting based on authenticated user, not IP. Use multiple factors for rate limit identification.",
		"Security":  "Implement all recommended security headers. Use strict CSP. Enable HSTS with preload.",
		"WebSocket": "Validate Origin header for WebSocket connections. Implement proper authentication for WebSocket endpoints.",
		"JWT":       "Always validate JWT signature server-side. Reject alg:none. Use asymmetric algorithms. Validate all claims.",
		"CRLF":      "Sanitize header values to reject CR/LF characters. Use framework-level header encoding.",
		"Cookie":    "Use secure session management with HttpOnly, Secure, SameSite flags. Regenerate session IDs after login.",
		"ContentType": "Enforce strict Content-Type validation. Set X-Content-Type-Options: nosniff.",
		"Redirect":    "Validate redirect targets against an allowlist. Never use user-supplied values in Location headers.",
		"Protocol":    "Disable h2c upgrades on public-facing servers. Validate Upgrade headers. Enforce TLS end-to-end.",
		"Encoding":    "Set explicit Content-Type and charset. Reject ambiguous encodings. Validate Range headers.",
		"Gateway":     "Strip untrusted gateway headers at edge. Validate API keys server-side. Disable debug modes in production.",
	}

	if r, ok := remediations[category]; ok {
		return r
	}
	return "Review and harden the application's header handling."
}

// verifyFindingStrict implements Rule #8: verification with 3 attempts
// Returns (verified, attempts). If all 3 fail → caller discards as FP.
func (o *Orchestrator) verifyFindingStrict(finding *Finding, mutation Mutation) (bool, int) {
	successes := 0
	attempts := 3

	for i := 0; i < attempts; i++ {
		ctx := o.buildMutationRequest(mutation)
		resp, err := ctx.Execute(o.client)
		if err != nil {
			continue
		}

		// During verification, a WAF block returns the same shape every time.
		// If we let it through, "3/3 successes" would falsely confirm the FP.
		if o.isRejectionResponse(resp) {
			o.recordFingerprint(mutation, resp)
			continue
		}

		diff := CalculateDiffWithProfile(o.baseline, resp, o.profile)

		reflected, reflectLocation := CheckHeaderReflection(mutation, resp, o.baseline)
		if reflected {
			diff.HeaderReflection = true
			diff.ReflectedValue = reflectLocation
		}

		// Use similarity engine for body changes
		if diff.BodyHashChanged {
			sim := CalculateSimilarityWithProfile(o.baseline, resp, o.profile)
			if sim.NormalizedBodySimilarity > 0.95 && sim.StructuralSimilarity > 0.95 {
				diff.BodyHashChanged = false
			}
		}

		if diff.IsSignificant() && !isVolatileOnly(diff) && !diff.IsCookieOnly() {
			successes++
		}

		if i < attempts-1 {
			time.Sleep(200 * time.Millisecond)
		}
	}

	if successes >= 2 {
		// Reproduced in at least 2/3 attempts → CONFIRMED
		finding.Verified = true
		finding.Reproducible = true
		finding.VerifiedAt = time.Now()
		finding.Evidence["verified"] = fmt.Sprintf("CONFIRMED (%d/%d runs)", successes, attempts)

		// Boost confidence: reproduced findings get HIGH or CONFIRMED
		finding.ConfidenceScore += 0.15
		if finding.ConfidenceScore > 1.0 {
			finding.ConfidenceScore = 1.0
		}
		finding.Confidence = confidenceLabelV2(finding.ConfidenceScore)
		return true, attempts
	}

	if successes == 1 {
		// Only 1/3 → downgrade confidence by 2 levels
		finding.ConfidenceScore -= 0.3
		if finding.ConfidenceScore < 0.2 {
			finding.ConfidenceScore = 0.2
		}
		finding.Confidence = confidenceLabelV2(finding.ConfidenceScore)
		finding.Evidence["verified"] = fmt.Sprintf("INCONSISTENT (%d/%d runs)", successes, attempts)
		return false, attempts
	}

	// 0/3 → FALSE POSITIVE — caller will discard
	return false, attempts
}

// confidenceLabelV2 implements Rule #7 confidence scoring
func confidenceLabelV2(score float64) string {
	if score >= 0.85 {
		return "Confirmed"
	}
	if score >= 0.6 {
		return "High"
	}
	if score >= 0.4 {
		return "Medium"
	}
	if score >= 0.2 {
		return "Low"
	}
	return "False Positive"
}

func (o *Orchestrator) prioritizeMutations(mutations []Mutation) []Mutation {
	if o.reconResult == nil {
		return mutations
	}

	reflectedSet := o.reconResult.ReflectedHeaderSet()
	if len(reflectedSet) == 0 {
		return mutations
	}

	var prioritized []Mutation
	var rest []Mutation

	for _, m := range mutations {
		headerLower := strings.ToLower(m.Header)
		if reflectedSet[headerLower] {
			prioritized = append(prioritized, m)
		} else {
			rest = append(rest, m)
		}
	}

	return append(prioritized, rest...)
}

func (o *Orchestrator) addFinding(finding Finding) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.findings = append(o.findings, finding)
}

func (o *Orchestrator) generateMutations() []Mutation {
	mutations := []Mutation{}

	type mutationSource struct {
		enabled bool
		getter  func() []Mutation
	}

	sources := []mutationSource{
		{o.config.Auth, GetAuthMutations},
		{o.config.Proxy, GetProxyMutations},
		{o.config.CORS, GetCORSMutations},
		{o.config.Cache, GetCacheMutations},
		{o.config.Override, GetOverrideMutations},
		{o.config.Cloud, GetCloudMutations},
		{o.config.Debug, GetDebugMutations},
		{o.config.Smuggling, GetSmugglingMutations},
		{o.config.Injection, GetInjectionMutations},
		{o.config.SSRF, GetSSRFMutations},
		{o.config.HopByHop, GetHopByHopMutations},
		{o.config.RateLimit, GetRateLimitMutations},
		{o.config.Security, GetSecurityMutations},
		{o.config.WebSocket, GetWebSocketMutations},
		{o.config.JWT, GetJWTMutations},
		{o.config.CRLF, GetCRLFMutations},
		{o.config.Cookie, GetCookieMutations},
		{o.config.ContentTypeCat, GetContentTypeMutations},
		{o.config.Redirect, GetRedirectMutations},
		{o.config.Protocol, GetProtocolMutations},
		{o.config.Encoding, GetEncodingMutations},
		{o.config.Gateway, GetGatewayMutations},
	}

	for _, src := range sources {
		if src.enabled && src.getter != nil {
			mutations = append(mutations, src.getter()...)
		}
	}

	return mutations
}

func (o *Orchestrator) countActiveCategories() int {
	count := 0
	flags := []bool{
		o.config.Auth, o.config.Proxy, o.config.CORS, o.config.Cache,
		o.config.Override, o.config.Cloud, o.config.Debug, o.config.Smuggling,
		o.config.Injection, o.config.SSRF, o.config.HopByHop, o.config.RateLimit,
		o.config.Security, o.config.WebSocket, o.config.JWT,
		o.config.CRLF, o.config.Cookie, o.config.ContentTypeCat, o.config.Redirect,
		o.config.Protocol, o.config.Encoding, o.config.Gateway,
	}
	for _, f := range flags {
		if f {
			count++
		}
	}
	return count
}

func (o *Orchestrator) calculateStats(totalMutations int, duration time.Duration) ScanStats {
	stats := ScanStats{
		TotalMutations: totalMutations,
		TotalFindings:  len(o.findings),
		Duration:       duration,
	}

	if o.baseline != nil {
		stats.BaselineStatus = o.baseline.StatusCode
		stats.BaselineSize = int64(len(o.baseline.Body))
		stats.BaselineTime = o.baseline.TimingMS
	}

	for _, f := range o.findings {
		switch f.Severity {
		case "Critical":
			stats.Critical++
		case "High":
			stats.High++
		case "Medium":
			stats.Medium++
		case "Low":
			stats.Low++
		default:
			stats.Info++
		}
	}

	return stats
}

func (o *Orchestrator) printAuditSummary(audit *SecurityAudit) {
	if audit.WAFDetected != "" {
		fmt.Printf("\033[0;35m[WAF]\033[0m Detected: \033[1m%s\033[0m\n", audit.WAFDetected)
	}
	if audit.ServerInfo != "" {
		fmt.Printf("\033[0;36m[SERVER]\033[0m %s\n", audit.ServerInfo)
	}
	if len(audit.TechFingerprints) > 0 {
		techs := []string{}
		for _, fp := range audit.TechFingerprints {
			if fp.Version != "" {
				techs = append(techs, fp.Technology+" ("+fp.Version+")")
			} else {
				techs = append(techs, fp.Technology)
			}
		}
		fmt.Printf("\033[0;36m[TECH]\033[0m %s\n", strings.Join(techs, " | "))
	}
	if len(audit.MissingHeaders) > 0 {
		fmt.Printf("\033[0;33m[AUDIT]\033[0m %d missing security headers\n", len(audit.MissingHeaders))
	}
	if len(audit.InformationLeaks) > 0 {
		fmt.Printf("\033[0;33m[AUDIT]\033[0m %d information leaks detected\n", len(audit.InformationLeaks))
	}
	if audit.CORSAnalysis != nil && audit.CORSAnalysis.Vulnerable {
		fmt.Printf("\033[0;31m[AUDIT]\033[0m CORS misconfiguration: %s\n", audit.CORSAnalysis.Details)
	}
}

func randomizeCase(s string) string {
	result := ""
	for i, c := range s {
		if i%2 == 0 {
			result += string(c)
		} else {
			if c >= 'a' && c <= 'z' {
				result += string(c - 32)
			} else if c >= 'A' && c <= 'Z' {
				result += string(c + 32)
			} else {
				result += string(c)
			}
		}
	}
	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
