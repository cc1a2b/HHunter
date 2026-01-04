package engine

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

var (
	GetAuthMutations     func() []Mutation
	GetProxyMutations    func() []Mutation
	GetCORSMutations     func() []Mutation
	GetCacheMutations    func() []Mutation
	GetOverrideMutations func() []Mutation
	GetCloudMutations    func() []Mutation
	GetDebugMutations    func() []Mutation
)

type ScanConfig struct {
	URL          string
	Method       string
	Headers      map[string]string
	Auth         bool
	Proxy        bool
	CORS         bool
	Cache        bool
	Override     bool
	Cloud        bool
	Debug        bool
	Chain        bool
	DiffOnly     bool
	PrivCheck    bool
	WAFEvasion   bool
	ProxyURL     string
	Workers      int
	RateLimit    int
	Stealth      bool
	Timeout      time.Duration
}

type Orchestrator struct {
	config   *ScanConfig
	client   *http.Client
	baseline *ResponseContext
	findings []Finding
	mu       sync.Mutex
}

func NewOrchestrator(config *ScanConfig) *Orchestrator {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}

	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Orchestrator{
		config:   config,
		client:   client,
		findings: []Finding{},
	}
}

func (o *Orchestrator) Scan() ([]Finding, error) {
	fmt.Println("\033[0;34m[INFO]\033[0m Starting HHunter scan...")

	baselineCtx := NewRequestContext(o.config.URL, o.config.Method)
	for k, v := range o.config.Headers {
		baselineCtx.AddHeader(k, v)
	}

	fmt.Println("\033[0;34m[INFO]\033[0m Establishing baseline...")
	baseline, err := baselineCtx.Execute(o.client)
	if err != nil {
		return nil, fmt.Errorf("baseline request failed: %w", err)
	}
	o.baseline = baseline
	fmt.Printf("\033[0;32m[+]\033[0m Baseline: %d (size: %d, time: %dms)\n", baseline.StatusCode, baseline.ContentLength, baseline.TimingMS)

	mutations := o.generateMutations()
	fmt.Printf("\033[0;34m[INFO]\033[0m Generated %d mutations\n", len(mutations))

	if o.config.Workers == 0 {
		o.config.Workers = 30
	}

	sem := make(chan struct{}, o.config.Workers)
	var wg sync.WaitGroup

	for i, mutation := range mutations {
		wg.Add(1)
		sem <- struct{}{}

		go func(idx int, mut Mutation) {
			defer wg.Done()
			defer func() { <-sem }()

			if o.config.RateLimit > 0 {
				time.Sleep(time.Duration(o.config.RateLimit) * time.Millisecond)
			}

			o.testMutation(mut, idx+1, len(mutations))
		}(i, mutation)
	}

	wg.Wait()
	fmt.Printf("\n\033[0;32m[SUCCESS]\033[0m Scan complete. Found %d findings.\n", len(o.findings))

	return o.findings, nil
}

func (o *Orchestrator) testMutation(mutation Mutation, current, total int) {
	ctx := NewRequestContext(o.config.URL, o.config.Method)
	for k, v := range o.config.Headers {
		ctx.AddHeader(k, v)
	}

	headerName := mutation.Header
	headerValue := mutation.Value

	if o.config.WAFEvasion {
		headerName = randomizeCase(headerName)
	}

	ctx.AddHeader(headerName, headerValue)

	resp, err := ctx.Execute(o.client)
	if err != nil {
		return
	}

	diff := CalculateDiff(o.baseline, resp)

	if o.config.DiffOnly && !diff.IsSignificant() {
		return
	}

	if diff.IsSignificant() {
		fmt.Printf("[%d/%d] %s: %s -> ", current, total, mutation.Header, mutation.Value)

		if diff.StatusChanged {
			fmt.Printf("%d->%d ", o.baseline.StatusCode, resp.StatusCode)
		}
		if diff.AuthBypass {
			fmt.Print("AUTH_BYPASS ")
		}
		if diff.PrivilegeElevate {
			fmt.Print("PRIV_ELEVATE ")
		}
		if len(diff.NewJSONKeys) > 0 {
			fmt.Printf("NEW_KEYS:%v ", diff.NewJSONKeys)
		}
		fmt.Println()

		finding := o.createFinding(mutation, diff, resp)
		o.addFinding(finding)
	}
}

func (o *Orchestrator) createFinding(mutation Mutation, diff *DiffResult, resp *ResponseContext) Finding {
	evidence := make(map[string]string)

	if diff.StatusChanged {
		evidence["status_change"] = fmt.Sprintf("%d → %d", o.baseline.StatusCode, resp.StatusCode)
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
	}
	if len(diff.HeadersAdded) > 0 {
		evidence["headers_added"] = fmt.Sprintf("%v", diff.HeadersAdded)
	}

	confidence := "Medium"
	if diff.AuthBypass || diff.PrivilegeElevate {
		confidence = "High"
	} else if diff.StatusChanged {
		confidence = "High"
	}

	severity := "Medium"
	if diff.AuthBypass {
		severity = "Critical"
	} else if diff.PrivilegeElevate {
		severity = "High"
	} else if diff.StatusChanged && o.baseline.StatusCode >= 400 && resp.StatusCode < 400 {
		severity = "High"
	}

	return Finding{
		Header:     mutation.Header,
		Payload:    mutation.Value,
		Impact:     mutation.Impact,
		Confidence: confidence,
		Evidence:   evidence,
		Category:   mutation.Category,
		Severity:   severity,
		Timestamp:  time.Now(),
	}
}

func (o *Orchestrator) addFinding(finding Finding) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.findings = append(o.findings, finding)
}

func (o *Orchestrator) generateMutations() []Mutation {
	mutations := []Mutation{}

	if o.config.Auth {
		mutations = append(mutations, GetAuthMutations()...)
	}
	if o.config.Proxy {
		mutations = append(mutations, GetProxyMutations()...)
	}
	if o.config.CORS {
		mutations = append(mutations, GetCORSMutations()...)
	}
	if o.config.Cache {
		mutations = append(mutations, GetCacheMutations()...)
	}
	if o.config.Override {
		mutations = append(mutations, GetOverrideMutations()...)
	}
	if o.config.Cloud {
		mutations = append(mutations, GetCloudMutations()...)
	}
	if o.config.Debug {
		mutations = append(mutations, GetDebugMutations()...)
	}

	return mutations
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
