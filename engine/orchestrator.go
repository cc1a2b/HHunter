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
	minConfidenceReport = 0.4
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
		config:           config,
		client:           client,
		findings:         []Finding{},
		confirmedHeaders: make(map[string]bool),
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
	ctx := NewRequestContext(o.config.URL, o.config.Method)
	for k, v := range o.config.Headers {
		ctx.AddHeader(k, v)
	}
	if len(o.config.Body) > 0 {
		ctx.SetBody(o.config.Body, o.config.ContentType)
	}

	// Handle chained mutations (multi-header)
	if strings.Contains(mutation.Header, " + ") {
		// Parse chained header format: "Header1 + Header2"
		// Value format: "Header1: val1 | Header2: val2"
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

	resp, err := ctx.Execute(o.client)
	if err != nil {
		return
	}

	// Apply match/filter rules
	if !o.matchesFilters(resp) {
		return
	}

	diff := CalculateDiffWithProfile(o.baseline, resp, o.profile)

	reflected, reflectLocation := CheckHeaderReflection(mutation, resp)
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

		// Rule #2: Content-Type injection is ONLY real if value reflects
		// in body or response Content-Type header changed to match
		if mutation.Category == "ContentType" {
			confirmed := false
			if strings.Contains(string(resp.Body), mutation.Value) {
				confirmed = true
			}
			if diff.ContentTypeChanged {
				mutatedCT := getHeaderValue(resp.Headers, "content-type")
				if strings.Contains(mutatedCT, mutation.Value) {
					confirmed = true
				}
			}
			if !confirmed {
				return
			}
		}

		finding := o.createFinding(mutation, diff, resp)

		if finding.ConfidenceScore >= minConfidenceReport {
			// Rule #3: Hop-by-hop auto-escalation to cache poisoning
			if mutation.Category == "HopByHop" {
				o.hopByHopEscalate(&finding)
			}

			// Smart verification
			if o.config.Verify && finding.ConfidenceScore > 0.6 {
				if o.verifyFinding(&finding, mutation) {
					o.mu.Lock()
					o.verified++
					o.mu.Unlock()
				}
			}

			o.printMutationResult(current, total, mutation, diff, resp)
			o.addFinding(finding)

			// Track confirmed headers for escalation phase (Rule #5)
			o.mu.Lock()
			o.confirmedHeaders[strings.ToLower(mutation.Header)] = true
			o.mu.Unlock()
		}
	}
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

	// Rule #4: Evidence-based confidence labeling
	confidenceLabel := "Low"
	if diff.HeaderReflection && strings.Contains(diff.ReflectedValue, "body:") {
		// Literal reflection in body → always CONFIRMED
		confidenceLabel = "Confirmed"
		if confidence < 0.8 {
			confidence = 0.8
		}
	} else if diff.ContentTypeChanged {
		// Response Content-Type hijacked → CONFIRMED
		confidenceLabel = "Confirmed"
		if confidence < 0.8 {
			confidence = 0.8
		}
	} else if confidence >= 0.8 {
		confidenceLabel = "Confirmed"
	} else if confidence >= 0.6 {
		confidenceLabel = "High"
	} else if confidence >= 0.4 {
		confidenceLabel = "Medium"
	}

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

func (o *Orchestrator) verifyFinding(finding *Finding, mutation Mutation) bool {
	ctx := NewRequestContext(o.config.URL, o.config.Method)
	for k, v := range o.config.Headers {
		ctx.AddHeader(k, v)
	}
	if len(o.config.Body) > 0 {
		ctx.SetBody(o.config.Body, o.config.ContentType)
	}

	// Handle chained mutations
	if strings.Contains(mutation.Header, " + ") {
		pairs := strings.Split(mutation.Value, " | ")
		for _, pair := range pairs {
			colonIdx := strings.Index(pair, ": ")
			if colonIdx > 0 {
				ctx.AddHeader(pair[:colonIdx], pair[colonIdx+2:])
			}
		}
	} else {
		ctx.AddHeader(mutation.Header, mutation.Value)
	}

	resp, err := ctx.Execute(o.client)
	if err != nil {
		return false
	}

	diff := CalculateDiffWithProfile(o.baseline, resp, o.profile)

	reflected, reflectLocation := CheckHeaderReflection(mutation, resp)
	if reflected {
		diff.HeaderReflection = true
		diff.ReflectedValue = reflectLocation
	}

	if !diff.IsSignificant() {
		return false
	}

	finding.Verified = true
	finding.VerifiedAt = time.Now()
	finding.Evidence["verified"] = "CONFIRMED"

	finding.ConfidenceScore += 0.15
	if finding.ConfidenceScore > 1.0 {
		finding.ConfidenceScore = 1.0
	}
	finding.Confidence = confidenceLabel(finding.ConfidenceScore)

	return true
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
