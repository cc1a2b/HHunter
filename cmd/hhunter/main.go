package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	dbg "runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/cc1a2b/HHunter/engine"
	"github.com/cc1a2b/HHunter/headers"
)

var version = "dev"

func init() {
	if version == "dev" {
		if info, ok := dbg.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
	}
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return strings.Join(*i, ", ")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var (
	// Target
	targetURL    string
	urlFile      string
	method       string
	requestBody  string
	contentType  string
	rawRequest   string

	// Attack categories
	auth        bool
	proxy       bool
	cors        bool
	cache       bool
	override    bool
	cloud       bool
	debug       bool
	smuggling   bool
	injection   bool
	ssrf        bool
	hopbyhop    bool
	ratelimit   bool
	security    bool
	websocket   bool
	jwt         bool
	crlf        bool
	cookieAtk   bool
	contenttypeAtk bool
	redirect    bool
	protocol    bool
	encoding    bool
	gateway     bool

	// Meta flags
	chain      bool
	diffOnly   bool
	privCheck  bool
	wafEvasion bool
	stealth    bool
	audit      bool
	recon      bool
	verify     bool
	full       bool

	// HTTP configuration
	proxyURL     string
	output       string
	workers      int
	rateLimit    int
	timeout      int
	customHeader arrayFlags
	cookieStr    string
	followRedir  bool

	// OOB
	oobEnabled bool
	oobAddr    string
	oobURL     string
	oobWait    int

	// Matchers/Filters
	matchStatus  string
	filterStatus string
	matchSize    int64
	filterSize   int64

	// Report
	reportFile string
	sarifFile  string

	// False-positive controls (v0.2.2)
	timingOnly bool
	showAll    bool
	verbose    bool
	scopeFile  string

	// UI
	showHelp bool
	update   bool
	quiet    bool
)

func init() {
	engine.GetAuthMutations = headers.GetAuthMutations
	engine.GetProxyMutations = headers.GetProxyMutations
	engine.GetCORSMutations = headers.GetCORSMutations
	engine.GetCacheMutations = headers.GetCacheMutations
	engine.GetOverrideMutations = headers.GetOverrideMutations
	engine.GetCloudMutations = headers.GetCloudMutations
	engine.GetDebugMutations = headers.GetDebugMutations
	engine.GetSmugglingMutations = headers.GetSmugglingMutations
	engine.GetInjectionMutations = headers.GetInjectionMutations
	engine.GetSSRFMutations = headers.GetSSRFMutations
	engine.GetHopByHopMutations = headers.GetHopByHopMutations
	engine.GetRateLimitMutations = headers.GetRateLimitMutations
	engine.GetSecurityMutations = headers.GetSecurityMutations
	engine.GetWebSocketMutations = headers.GetWebSocketMutations
	engine.GetJWTMutations = headers.GetJWTMutations
	engine.GetCRLFMutations = headers.GetCRLFMutations
	engine.GetCookieMutations = headers.GetCookieMutations
	engine.GetContentTypeMutations = headers.GetContentTypeMutations
	engine.GetRedirectMutations = headers.GetRedirectMutations
	engine.GetProtocolMutations = headers.GetProtocolMutations
	engine.GetEncodingMutations = headers.GetEncodingMutations
	engine.GetGatewayMutations = headers.GetGatewayMutations
}

func main() {
	// Target
	flag.StringVar(&targetURL, "u", "", "Target URL")
	flag.StringVar(&targetURL, "url", "", "Target URL")
	flag.StringVar(&urlFile, "l", "", "File containing list of URLs (one per line)")
	flag.StringVar(&urlFile, "list", "", "File containing list of URLs (one per line)")
	flag.StringVar(&method, "m", "GET", "HTTP method")
	flag.StringVar(&method, "method", "GET", "HTTP method")
	flag.StringVar(&requestBody, "d", "", "Request body data")
	flag.StringVar(&requestBody, "data", "", "Request body data")
	flag.StringVar(&contentType, "ct", "", "Content-Type for request body")
	flag.StringVar(&rawRequest, "raw", "", "File containing raw HTTP request (Burp format)")

	// Core categories
	flag.BoolVar(&auth, "auth", false, "Test authentication & authorization bypass")
	flag.BoolVar(&proxy, "proxy", false, "Test proxy trust headers")
	flag.BoolVar(&cors, "cors", false, "Test CORS misconfigurations")
	flag.BoolVar(&cache, "cache", false, "Test cache poisoning vulnerabilities")
	flag.BoolVar(&override, "override", false, "Test HTTP method override attacks")
	flag.BoolVar(&cloud, "cloud", false, "Test cloud/CDN header injections")
	flag.BoolVar(&debug, "debug", false, "Test debug header exposure")

	// Advanced categories
	flag.BoolVar(&smuggling, "smuggling", false, "Test HTTP request smuggling indicators")
	flag.BoolVar(&injection, "injection", false, "Test header injection (XSS, SSTI, Log4Shell, SQLi)")
	flag.BoolVar(&ssrf, "ssrf", false, "Test SSRF via header manipulation")
	flag.BoolVar(&hopbyhop, "hopbyhop", false, "Test hop-by-hop header abuse")
	flag.BoolVar(&ratelimit, "ratelimit", false, "Test rate limit bypass techniques")
	flag.BoolVar(&security, "security", false, "Test security header manipulation")
	flag.BoolVar(&websocket, "websocket", false, "Test WebSocket/gRPC/GraphQL probes")
	flag.BoolVar(&jwt, "jwt", false, "Test JWT attacks (alg:none, confusion, injection)")
	flag.BoolVar(&crlf, "crlf", false, "Test CRLF injection / HTTP response splitting")
	flag.BoolVar(&cookieAtk, "cookie", false, "Test cookie manipulation (fixation, tossing, overflow)")
	flag.BoolVar(&contenttypeAtk, "content-type", false, "Test Content-Type abuse (MIME confusion, WAF bypass)")
	flag.BoolVar(&redirect, "redirect", false, "Test open redirect via header manipulation")
	flag.BoolVar(&protocol, "protocol", false, "Test protocol upgrade attacks (h2c smuggling, HTTP/2)")
	flag.BoolVar(&encoding, "encoding", false, "Test encoding/charset attacks (WAF bypass, compression oracle)")
	flag.BoolVar(&gateway, "gateway", false, "Test API gateway/routing bypass (Kong, Envoy, Traefik)")

	// Meta flags
	flag.BoolVar(&full, "full", false, "Run ALL categories + audit + recon + verify + chain")
	flag.BoolVar(&audit, "audit", false, "Run passive security audit (WAF, tech fingerprint, missing headers)")
	flag.BoolVar(&recon, "recon", false, "Run reconnaissance phase (reflection, method discovery, host injection)")
	flag.BoolVar(&verify, "verify", false, "Auto-verify high-confidence findings by re-sending mutations")
	flag.BoolVar(&chain, "chain", false, "Chain multiple header mutations for combo attacks")
	flag.BoolVar(&diffOnly, "diff-only", false, "Only show significant response differences")
	flag.BoolVar(&privCheck, "priv-check", false, "Check for privilege escalation")
	flag.BoolVar(&wafEvasion, "waf-evasion", false, "Enable WAF bypass techniques")
	flag.BoolVar(&stealth, "stealth", false, "Stealth mode (slower, more evasive)")

	// HTTP configuration
	flag.StringVar(&proxyURL, "proxy-url", "", "HTTP proxy URL (e.g., http://127.0.0.1:8080)")
	flag.StringVar(&output, "o", "", "Output file (JSON)")
	flag.StringVar(&output, "output", "", "Output file (JSON)")
	flag.IntVar(&workers, "w", 30, "Number of concurrent workers")
	flag.IntVar(&workers, "workers", 30, "Number of concurrent workers")
	flag.IntVar(&rateLimit, "r", 0, "Rate limit delay in milliseconds")
	flag.IntVar(&rateLimit, "rate", 0, "Rate limit delay in milliseconds")
	flag.IntVar(&timeout, "t", 30, "Request timeout in seconds")
	flag.IntVar(&timeout, "timeout", 30, "Request timeout in seconds")
	flag.Var(&customHeader, "H", "Custom header (can be used multiple times)")
	flag.Var(&customHeader, "header", "Custom header (can be used multiple times)")
	flag.StringVar(&cookieStr, "b", "", "Cookie string (e.g., \"session=abc123; token=xyz\")")
	flag.StringVar(&cookieStr, "cookies", "", "Cookie string (e.g., \"session=abc123; token=xyz\")")
	flag.BoolVar(&followRedir, "fr", false, "Follow redirects")
	flag.BoolVar(&followRedir, "follow-redirect", false, "Follow redirects")

	// OOB (Out-of-Band)
	flag.BoolVar(&oobEnabled, "oob", false, "Enable OOB callback server for blind vulnerability detection")
	flag.StringVar(&oobAddr, "oob-addr", "0.0.0.0:8888", "OOB callback server listen address")
	flag.StringVar(&oobURL, "oob-url", "", "External URL for OOB callbacks (e.g., http://your-vps:8888)")
	flag.IntVar(&oobWait, "oob-wait", 10, "Seconds to wait for OOB callbacks after scan")

	// Matchers/Filters
	flag.StringVar(&matchStatus, "ms", "", "Match status codes (comma-separated, e.g., 200,302)")
	flag.StringVar(&matchStatus, "match-status", "", "Match status codes (comma-separated)")
	flag.StringVar(&filterStatus, "fs", "", "Filter (exclude) status codes (comma-separated)")
	flag.StringVar(&filterStatus, "filter-status", "", "Filter (exclude) status codes (comma-separated)")
	flag.Int64Var(&matchSize, "match-size", 0, "Match response size (bytes)")
	flag.Int64Var(&filterSize, "filter-size", 0, "Filter (exclude) response size (bytes)")

	// False-positive controls
	flag.BoolVar(&timingOnly, "timing-only", false, "Show timing-only findings (research mode)")
	flag.BoolVar(&showAll, "all", false, "Show ALL findings including LOW and timing-only")
	flag.BoolVar(&verbose, "verbose", false, "Show normalized diff details for each finding")
	flag.StringVar(&scopeFile, "scope", "", "Scope file with out-of-scope rules (one per line)")

	// Report
	flag.StringVar(&reportFile, "report", "", "Generate HTML report (filename.html)")
	flag.StringVar(&sarifFile, "sarif", "", "Generate SARIF report for CI/CD (filename.sarif)")

	// UI
	flag.BoolVar(&showHelp, "h", false, "Show help")
	flag.BoolVar(&showHelp, "help", false, "Show help")
	flag.BoolVar(&update, "update", false, "Update to latest version")
	flag.BoolVar(&update, "up", false, "Update to latest version")
	flag.BoolVar(&quiet, "q", false, "Quiet mode: suppress banner")
	flag.BoolVar(&quiet, "quiet", false, "Quiet mode: suppress banner")

	flag.Parse()

	if showHelp {
		printBanner()
		printHelp()
		os.Exit(0)
	}

	if update {
		printBanner()
		updateTool()
		return
	}

	// Determine target URLs
	urls := collectTargetURLs()
	if len(urls) == 0 {
		printBanner()
		printHelp()
		os.Exit(0)
	}

	if !quiet {
		printBanner()
	}

	// Apply --full
	if full {
		auth = true
		proxy = true
		cors = true
		cache = true
		override = true
		cloud = true
		debug = true
		smuggling = true
		injection = true
		ssrf = true
		hopbyhop = true
		ratelimit = true
		security = true
		websocket = true
		jwt = true
		crlf = true
		cookieAtk = true
		contenttypeAtk = true
		redirect = true
		protocol = true
		encoding = true
		gateway = true
		audit = true
		recon = true
		verify = true
		chain = true
	}

	// Default categories if none selected
	noCategory := !auth && !proxy && !cors && !cache && !override && !cloud && !debug &&
		!smuggling && !injection && !ssrf && !hopbyhop && !ratelimit && !security && !websocket && !jwt &&
		!crlf && !cookieAtk && !contenttypeAtk && !redirect && !protocol && !encoding && !gateway

	if noCategory {
		fmt.Println("\033[0;33m[!]\033[0m No test categories specified. Running core tests + audit...")
		auth = true
		proxy = true
		cors = true
		cache = true
		override = true
		cloud = true
		debug = true
		audit = true
	}

	// Parse custom headers
	headerMap := make(map[string]string)
	for _, h := range customHeader {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Add cookie header
	if cookieStr != "" {
		headerMap["Cookie"] = cookieStr
	}

	// Parse match/filter status codes
	matchStatusCodes := parseStatusCodes(matchStatus)
	filterStatusCodes := parseStatusCodes(filterStatus)

	// Parse scope file
	var scopeRules []string
	if scopeFile != "" {
		scopeData, err := os.ReadFile(scopeFile)
		if err != nil {
			fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to read scope file: %v\n", err)
			os.Exit(1)
		}
		for _, line := range strings.Split(string(scopeData), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				scopeRules = append(scopeRules, line)
			}
		}
		fmt.Printf("\033[0;34m[SCOPE]\033[0m Loaded %d scope rules from %s\n", len(scopeRules), scopeFile)
	}

	// Start OOB server if enabled
	var oobServer *engine.OOBServer
	if oobEnabled {
		oobServer = engine.NewOOBServer(oobAddr, oobURL)
		if err := oobServer.Start(); err != nil {
			fmt.Printf("\033[0;31m[ERROR]\033[0m OOB server failed: %v\n", err)
			os.Exit(1)
		}
		defer oobServer.Stop()
	}

	// Handle raw request file
	var rawBody []byte
	if rawRequest != "" {
		rawData, err := os.ReadFile(rawRequest)
		if err != nil {
			fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to read raw request file: %v\n", err)
			os.Exit(1)
		}
		rc, err := engine.ParseRawRequest(string(rawData), strings.HasPrefix(targetURL, "https"))
		if err != nil {
			fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to parse raw request: %v\n", err)
			os.Exit(1)
		}
		if targetURL == "" {
			targetURL = rc.URL
		}
		method = rc.Method
		for k, v := range rc.Headers {
			headerMap[k] = v
		}
		if len(rc.Body) > 0 {
			rawBody = rc.Body
		}
		urls = []string{targetURL}
	}

	// Determine body
	var body []byte
	if requestBody != "" {
		body = []byte(requestBody)
	} else if rawBody != nil {
		body = rawBody
	}

	if len(body) > 0 && contentType == "" {
		// Auto-detect content type
		if body[0] == '{' || body[0] == '[' {
			contentType = "application/json"
		} else if strings.Contains(string(body), "=") {
			contentType = "application/x-www-form-urlencoded"
		}
	}

	// Scan all targets
	var allResults []*engine.ScanResult

	for i, u := range urls {
		if len(urls) > 1 {
			fmt.Printf("\n\033[1;36m[TARGET %d/%d]\033[0m %s\n", i+1, len(urls), u)
			fmt.Println(strings.Repeat("=", 60))
		}

		config := &engine.ScanConfig{
			URL:             u,
			Method:          method,
			Headers:         headerMap,
			Body:            body,
			ContentType:     contentType,
			Auth:            auth,
			Proxy:           proxy,
			CORS:            cors,
			Cache:           cache,
			Override:        override,
			Cloud:           cloud,
			Debug:           debug,
			Smuggling:       smuggling,
			Injection:       injection,
			SSRF:            ssrf,
			HopByHop:        hopbyhop,
			RateLimit:       ratelimit,
			Security:        security,
			WebSocket:       websocket,
			JWT:             jwt,
			CRLF:            crlf,
			Cookie:          cookieAtk,
			ContentTypeCat:  contenttypeAtk,
			Redirect:        redirect,
			Protocol:        protocol,
			Encoding:        encoding,
			Gateway:         gateway,
			Chain:           chain,
			DiffOnly:        diffOnly,
			PrivCheck:       privCheck,
			WAFEvasion:      wafEvasion,
			Audit:           audit,
			Recon:           recon,
			Verify:          verify,
			ProxyURL:        proxyURL,
			Workers:         workers,
			RateDelay:       rateLimit,
			Stealth:         stealth,
			Timeout:         time.Duration(timeout) * time.Second,
			OOBServer:       oobServer,
			OOBWait:         time.Duration(oobWait) * time.Second,
			FollowRedirects: followRedir,
			MatchStatus:     matchStatusCodes,
			FilterStatus:    filterStatusCodes,
			MatchSize:       matchSize,
			FilterSize:      filterSize,
			TimingOnly:      timingOnly,
			ShowAll:         showAll,
			Verbose:         verbose,
			ScopeRules:      scopeRules,
		}

		orchestrator := engine.NewOrchestrator(config)

		result, err := orchestrator.Scan()
		if err != nil {
			fmt.Printf("\033[31m[!] Scan failed for %s: %v\033[0m\n", u, err)
			continue
		}

		allResults = append(allResults, result)

		if result.Recon != nil {
			printReconSummary(result.Recon)
		}

		printFindings(result)
		printStats(result.Stats)

		if audit && result.SecurityAudit != nil {
			printSecurityAudit(result.SecurityAudit)
		}
	}

	// Save combined results
	if output != "" && len(allResults) > 0 {
		if len(allResults) == 1 {
			saveResults(allResults[0], output)
		} else {
			saveMultiResults(allResults, output)
		}
	}

	// Generate HTML report
	if reportFile != "" && len(allResults) > 0 {
		combined := combineResults(allResults)
		targetStr := targetURL
		if len(urls) > 1 {
			targetStr = fmt.Sprintf("%d targets", len(urls))
		}
		if err := engine.GenerateHTMLReport(combined, targetStr, reportFile); err != nil {
			fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to generate HTML report: %v\n", err)
		} else {
			fmt.Printf("\033[0;32m[REPORT]\033[0m HTML report saved to: %s\n", reportFile)
		}
	}

	// Generate SARIF report
	if sarifFile != "" && len(allResults) > 0 {
		combined := combineResults(allResults)
		targetStr := targetURL
		if len(urls) > 1 {
			targetStr = fmt.Sprintf("%d targets", len(urls))
		}
		if err := engine.GenerateSARIF(combined, targetStr, sarifFile); err != nil {
			fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to generate SARIF report: %v\n", err)
		} else {
			fmt.Printf("\033[0;32m[SARIF]\033[0m SARIF report saved to: %s\n", sarifFile)
		}
	}

	// Exit code based on findings
	if len(allResults) > 0 {
		totalCritical := 0
		totalHigh := 0
		for _, r := range allResults {
			totalCritical += r.Stats.Critical
			totalHigh += r.Stats.High
		}
		if totalCritical > 0 || totalHigh > 0 {
			os.Exit(1) // Non-zero exit for CI/CD integration
		}
	}
}

// collectTargetURLs gathers URLs from all sources: -u, -l, stdin
func collectTargetURLs() []string {
	var urls []string

	// From -u flag
	if targetURL != "" {
		urls = append(urls, targetURL)
	}

	// From -l file
	if urlFile != "" {
		fileURLs, err := readURLsFromFile(urlFile)
		if err != nil {
			fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to read URL file: %v\n", err)
			os.Exit(1)
		}
		urls = append(urls, fileURLs...)
	}

	// From stdin (pipe mode)
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && (strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://")) {
				urls = append(urls, line)
			}
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, u := range urls {
		if !seen[u] {
			seen[u] = true
			unique = append(unique, u)
		}
	}

	return unique
}

func readURLsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}
	return urls, scanner.Err()
}

func parseStatusCodes(s string) []int {
	if s == "" {
		return nil
	}
	var codes []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if code, err := strconv.Atoi(part); err == nil {
			codes = append(codes, code)
		}
	}
	return codes
}

func combineResults(results []*engine.ScanResult) *engine.ScanResult {
	if len(results) == 1 {
		return results[0]
	}

	combined := &engine.ScanResult{}
	for _, r := range results {
		combined.Findings = append(combined.Findings, r.Findings...)
		combined.Stats.TotalMutations += r.Stats.TotalMutations
		combined.Stats.TotalFindings += r.Stats.TotalFindings
		combined.Stats.Critical += r.Stats.Critical
		combined.Stats.High += r.Stats.High
		combined.Stats.Medium += r.Stats.Medium
		combined.Stats.Low += r.Stats.Low
		combined.Stats.Info += r.Stats.Info
		combined.Stats.Duration += r.Stats.Duration
		combined.Stats.ReconRequests += r.Stats.ReconRequests
		combined.Stats.VerifiedFindings += r.Stats.VerifiedFindings
		combined.Stats.OOBConfirmed += r.Stats.OOBConfirmed

		// Take first non-nil audit/recon
		if combined.SecurityAudit == nil && r.SecurityAudit != nil {
			combined.SecurityAudit = r.SecurityAudit
		}
		if combined.Recon == nil && r.Recon != nil {
			combined.Recon = r.Recon
		}
	}
	return combined
}

func printBanner() {
	versionStatus := getVersionStatus()
	var statusColor, statusText string

	switch versionStatus {
	case "latest":
		statusColor = "\033[0;32m"
		statusText = "latest"
	case "outdated":
		statusColor = "\033[0;31m"
		statusText = "outdated"
	default:
		statusColor = "\033[0;33m"
		statusText = "Unknown"
	}

	fmt.Printf(`
     __  ____  __            __
    / / / / / / /_  ______  / /____  _____
   / /_/ / /_/ / / / / __ \/ __/ _ \/ ___/
  / __  / __  / /_/ / / / / /_/  __/ /
 /_/ /_/_/ /_/\__,_/_/ /_/\__/\___/_/

 %s (%s%s%s)                  Created by cc1a2b

`, version, statusColor, statusText, "\033[0m")
}

func getVersionStatus() string {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/cc1a2b/HHunter/releases/latest")
	if err != nil {
		return "Unknown"
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "Unknown"
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Unknown"
	}

	var release struct {
		TagName string `json:"tag_name"`
	}

	if err := json.Unmarshal(body, &release); err != nil {
		return "Unknown"
	}

	if release.TagName == version {
		return "latest"
	}
	return "outdated"
}

func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("  hhunter -u <URL> [options]")
	fmt.Println("  hhunter -l <file> [options]")
	fmt.Println("  cat urls.txt | hhunter [options]")
	fmt.Println()

	fmt.Println("Target:")
	fmt.Println("  -u, --url URL                 Target URL")
	fmt.Println("  -l, --list FILE               File containing URLs (one per line)")
	fmt.Println("  -m, --method METHOD           HTTP method (default: GET)")
	fmt.Println("  -d, --data DATA               Request body data")
	fmt.Println("  -ct CONTENT-TYPE              Content-Type for request body")
	fmt.Println("  --raw FILE                    Raw HTTP request file (Burp format)")
	fmt.Println("  stdin                         Pipe URLs from other tools")
	fmt.Println()

	fmt.Println("Core Attack Categories:")
	fmt.Println("  --auth                        Authentication & authorization bypass")
	fmt.Println("  --proxy                       Proxy trust abuse (X-Forwarded-For, etc)")
	fmt.Println("  --cors                        CORS misconfigurations")
	fmt.Println("  --cache                       Cache poisoning & deception")
	fmt.Println("  --override                    HTTP method & URL override")
	fmt.Println("  --cloud                       Cloud/CDN/K8s header injection")
	fmt.Println("  --debug                       Debug mode & feature flag exposure")
	fmt.Println()

	fmt.Println("Advanced Attack Categories:")
	fmt.Println("  --smuggling                   HTTP request smuggling (CL-TE, TE-CL)")
	fmt.Println("  --injection                   Header injection (XSS, SSTI, Log4Shell, SQLi)")
	fmt.Println("  --ssrf                        SSRF via headers (metadata, internal services)")
	fmt.Println("  --hopbyhop                    Hop-by-hop header stripping attacks")
	fmt.Println("  --ratelimit                   Rate limit bypass techniques")
	fmt.Println("  --security                    Security header manipulation (CSP, HSTS)")
	fmt.Println("  --websocket                   WebSocket/gRPC/GraphQL probes")
	fmt.Println("  --jwt                         JWT attacks (alg:none, confusion, injection)")
	fmt.Println("  --crlf                        CRLF injection / HTTP response splitting")
	fmt.Println("  --cookie                      Cookie manipulation (fixation, tossing, overflow)")
	fmt.Println("  --content-type                Content-Type abuse (MIME confusion, WAF bypass)")
	fmt.Println("  --redirect                    Open redirect via header manipulation")
	fmt.Println("  --protocol                    Protocol upgrade (h2c smuggling, HTTP/2)")
	fmt.Println("  --encoding                    Encoding/charset attacks (WAF bypass, Range)")
	fmt.Println("  --gateway                     API gateway/routing bypass (Kong, Envoy, etc)")
	fmt.Println()

	fmt.Println("Scan Control:")
	fmt.Println("  --full                        Run ALL categories + audit + recon + verify + chain")
	fmt.Println("  --audit                       Passive security audit (WAF, tech, headers)")
	fmt.Println("  --recon                       Reconnaissance (reflection, methods, host injection)")
	fmt.Println("  --verify                      Auto-verify high-confidence findings")
	fmt.Println("  --chain                       Chain multiple header mutations for combo attacks")
	fmt.Println("  --diff-only                   Only show significant differences")
	fmt.Println("  --priv-check                  Privilege escalation detection")
	fmt.Println("  --waf-evasion                 WAF bypass techniques (header case randomization)")
	fmt.Println("  --stealth                     Stealth mode (slower, more evasive)")
	fmt.Println()

	fmt.Println("False-Positive Controls:")
	fmt.Println("  --timing-only                 Show timing-only findings (research mode)")
	fmt.Println("  --all                         Show ALL findings (including LOW and timing-only)")
	fmt.Println("  --verbose                     Show normalized diff for each finding")
	fmt.Println("  --scope FILE                  Scope file with out-of-scope rules (one per line)")
	fmt.Println()

	fmt.Println("OOB (Out-of-Band) Detection:")
	fmt.Println("  --oob                         Enable OOB callback server for blind vulns")
	fmt.Println("  --oob-addr ADDR               OOB listen address (default: 0.0.0.0:8888)")
	fmt.Println("  --oob-url URL                 External OOB URL (e.g., http://your-vps:8888)")
	fmt.Println("  --oob-wait SEC                Wait time for OOB callbacks (default: 10)")
	fmt.Println()

	fmt.Println("HTTP Configuration:")
	fmt.Println("  -w, --workers INT             Concurrent workers (default: 30)")
	fmt.Println("  -r, --rate MS                 Rate limit delay in milliseconds")
	fmt.Println("  -t, --timeout SEC             Request timeout in seconds (default: 30)")
	fmt.Println("  -H, --header \"Key: Value\"     Custom header (repeatable)")
	fmt.Println("  -b, --cookies \"key=val; ...\"  Cookie string")
	fmt.Println("  --proxy-url URL               HTTP proxy (e.g., http://127.0.0.1:8080)")
	fmt.Println("  -fr, --follow-redirect        Follow HTTP redirects")
	fmt.Println()

	fmt.Println("Matchers/Filters:")
	fmt.Println("  -ms, --match-status CODES     Only process these status codes (e.g., 200,302)")
	fmt.Println("  -fs, --filter-status CODES    Exclude these status codes (e.g., 404,500)")
	fmt.Println("  --match-size BYTES            Only process responses of this size")
	fmt.Println("  --filter-size BYTES           Exclude responses of this size")
	fmt.Println()

	fmt.Println("Output:")
	fmt.Println("  -o, --output FILE.json        Output results to JSON file")
	fmt.Println("  --report FILE.html            Generate HTML report")
	fmt.Println("  --sarif FILE.sarif            Generate SARIF report (CI/CD)")
	fmt.Println("  -q, --quiet                   Suppress banner")
	fmt.Println("  --update, --up                Update to latest version")
	fmt.Println("  -h, --help                    Show this help")
	fmt.Println()

	fmt.Println("Examples:")
	fmt.Println("  # Quick auth bypass test")
	fmt.Println("  hhunter -u https://api.target.com/admin --auth --jwt")
	fmt.Println()
	fmt.Println("  # Full offensive scan with OOB detection")
	fmt.Println("  hhunter -u https://target.com/api --full --oob --oob-url http://vps:8888 -o results.json")
	fmt.Println()
	fmt.Println("  # Multi-target scan from file with HTML report")
	fmt.Println("  hhunter -l urls.txt --full --report report.html")
	fmt.Println()
	fmt.Println("  # Pipeline mode from other tools")
	fmt.Println("  cat urls.txt | hhunter --auth --proxy --diff-only")
	fmt.Println()
	fmt.Println("  # POST endpoint with body data")
	fmt.Println("  hhunter -u https://api.target.com/login -m POST -d '{\"user\":\"admin\"}' --auth --injection")
	fmt.Println()
	fmt.Println("  # SSRF + injection through Burp with OOB")
	fmt.Println("  hhunter -u https://target.com --ssrf --injection --oob --proxy-url http://127.0.0.1:8080")
	fmt.Println()
	fmt.Println("  # Stealth scan with WAF evasion and filters")
	fmt.Println("  hhunter -u https://target.com --full --waf-evasion --stealth -fs 403,429 -w 5")
	fmt.Println()
	fmt.Println("  # Import raw request from Burp")
	fmt.Println("  hhunter --raw request.txt --auth --proxy --verify")
}

func printFindings(result *engine.ScanResult) {
	findings := result.Findings

	if len(findings) == 0 {
		fmt.Println("\n\033[0;34m[RESULT]\033[0m No vulnerabilities found")
		return
	}

	fmt.Printf("\n\033[0;31m[FOUND]\033[0m Discovered \033[1m%d\033[0m potential vulnerabilities\n\n", len(findings))

	for i, finding := range findings {
		fmt.Println("\033[0;33m" + strings.Repeat("\u2500", 60) + "\033[0m")
		fmt.Printf("\033[0;31m[!]\033[0m Finding #%d\n", i+1)
		fmt.Printf("  \033[0;36mHeader\033[0m:      %s\n", finding.Header)
		fmt.Printf("  \033[0;36mPayload\033[0m:     %s\n", truncateStr(finding.Payload, 80))
		fmt.Printf("  \033[0;36mImpact\033[0m:      %s\n", finding.Impact)
		fmt.Printf("  \033[0;36mCategory\033[0m:    %s\n", finding.Category)
		fmt.Printf("  \033[0;36mSeverity\033[0m:    %s\n", getSeverityColor(finding.Severity))
		fmt.Printf("  \033[0;36mConfidence\033[0m:  %s (%.0f%%)\n", finding.Confidence, finding.ConfidenceScore*100)

		if finding.Verified {
			verified := "CONFIRMED"
			if finding.Reproducible {
				verified = "CONFIRMED (reproducible)"
			}
			fmt.Printf("  \033[0;32mVerified\033[0m:    \033[1;32m%s\033[0m\n", verified)
		}
		if finding.VerifyAttempts > 0 && !finding.Verified {
			fmt.Printf("  \033[0;33mVerified\033[0m:    \033[0;33mINCONSISTENT (%d attempts)\033[0m\n", finding.VerifyAttempts)
		}
		if finding.TimingOnly {
			fmt.Printf("  \033[0;33mNote\033[0m:        \033[0;33mTiming-only finding (no structural signal)\033[0m\n")
		}
		if finding.ScopeNote != "" {
			fmt.Printf("  \033[0;33mScope\033[0m:       \033[0;33m%s\033[0m\n", finding.ScopeNote)
		}
		if finding.Evidence["oob_confirmed"] == "true" {
			fmt.Printf("  \033[0;35mOOB\033[0m:         \033[1;35mBLIND VULN CONFIRMED\033[0m\n")
		}
		if finding.ReconSource != "" {
			fmt.Printf("  \033[0;36mSource\033[0m:      Recon (%s)\n", finding.ReconSource)
		}
		if finding.Evidence["total_variants"] != "" {
			fmt.Printf("  \033[0;36mVariants\033[0m:    %s payloads trigger this\n", finding.Evidence["total_variants"])
		}

		if finding.CVSS > 0 {
			fmt.Printf("  \033[0;36mCVSS\033[0m:        %.1f\n", finding.CVSS)
		}
		if finding.CWE != "" {
			fmt.Printf("  \033[0;36mCWE\033[0m:         %s\n", finding.CWE)
		}

		if len(finding.Evidence) > 0 {
			fmt.Printf("  \033[0;36mEvidence\033[0m:\n")
			for k, v := range finding.Evidence {
				if k == "total_variants" || k == "alternate_triggers" {
					continue // Already displayed above
				}
				fmt.Printf("    - %s: %s\n", k, truncateStr(v, 100))
			}
		}

		if finding.CurlCommand != "" {
			fmt.Printf("  \033[0;36mReproduce\033[0m:\n    \033[0;32m%s\033[0m\n", finding.CurlCommand)
		}

		if finding.Remediation != "" {
			fmt.Printf("  \033[0;36mRemediation\033[0m: %s\n", finding.Remediation)
		}
	}
	fmt.Println("\033[0;33m" + strings.Repeat("\u2500", 60) + "\033[0m")
}

func printStats(stats engine.ScanStats) {
	fmt.Println()
	fmt.Println("\033[1mScan Summary:\033[0m")
	fmt.Printf("  Mutations tested: %d\n", stats.TotalMutations)
	if stats.ReconRequests > 0 {
		fmt.Printf("  Recon requests:   %d\n", stats.ReconRequests)
	}
	if stats.ChainsTested > 0 {
		fmt.Printf("  Chain combos:     %d\n", stats.ChainsTested)
	}
	fmt.Printf("  Findings:         %d\n", stats.TotalFindings)
	if stats.VerifiedFindings > 0 {
		fmt.Printf("  Verified:         \033[1;32m%d\033[0m\n", stats.VerifiedFindings)
	}
	if stats.OOBConfirmed > 0 {
		fmt.Printf("  OOB Confirmed:    \033[1;35m%d\033[0m\n", stats.OOBConfirmed)
	}
	if stats.TotalFindings > 0 {
		fmt.Printf("  Severity:         ")
		parts := []string{}
		if stats.Critical > 0 {
			parts = append(parts, fmt.Sprintf("\033[1;31m%d Critical\033[0m", stats.Critical))
		}
		if stats.High > 0 {
			parts = append(parts, fmt.Sprintf("\033[0;31m%d High\033[0m", stats.High))
		}
		if stats.Medium > 0 {
			parts = append(parts, fmt.Sprintf("\033[0;33m%d Medium\033[0m", stats.Medium))
		}
		if stats.Low > 0 {
			parts = append(parts, fmt.Sprintf("\033[0;32m%d Low\033[0m", stats.Low))
		}
		if stats.Info > 0 {
			parts = append(parts, fmt.Sprintf("\033[0;34m%d Info\033[0m", stats.Info))
		}
		fmt.Println(strings.Join(parts, " | "))
	}
	fmt.Printf("  Duration:         %s\n", stats.Duration.Round(time.Millisecond))
}

func printReconSummary(recon *engine.ReconSummary) {
	fmt.Println()
	fmt.Println("\033[1mReconnaissance Summary:\033[0m")
	fmt.Println("\033[0;33m" + strings.Repeat("\u2500", 60) + "\033[0m")

	if len(recon.ReflectedHeaders) > 0 {
		fmt.Printf("  \033[0;35mReflected Headers\033[0m:  %s\n", strings.Join(recon.ReflectedHeaders, ", "))
	} else {
		fmt.Println("  \033[0;34mReflected Headers\033[0m:  None detected")
	}

	if len(recon.AllowedMethods) > 0 {
		fmt.Printf("  \033[0;36mAllowed Methods\033[0m:    %s\n", strings.Join(recon.AllowedMethods, ", "))
	}
	if len(recon.DangerousMethods) > 0 {
		fmt.Printf("  \033[0;31mDangerous Methods\033[0m:  %s\n", strings.Join(recon.DangerousMethods, ", "))
	}
	if recon.TraceEnabled {
		fmt.Println("  \033[0;31mTRACE\033[0m:              Enabled")
	}
	if recon.VerbTamperBypasses > 0 {
		fmt.Printf("  \033[0;31mVerb Tamper Bypass\033[0m:  %d method(s) bypass auth\n", recon.VerbTamperBypasses)
	}
	if len(recon.HostInjectable) > 0 {
		fmt.Printf("  \033[0;31mHost Injectable\033[0m:    %s\n", strings.Join(recon.HostInjectable, ", "))
	}

	fmt.Println("\033[0;33m" + strings.Repeat("\u2500", 60) + "\033[0m")
}

func printSecurityAudit(auditResult *engine.SecurityAudit) {
	fmt.Println()
	fmt.Println("\033[1mPassive Security Audit:\033[0m")
	fmt.Println("\033[0;33m" + strings.Repeat("\u2500", 60) + "\033[0m")

	if auditResult.WAFDetected != "" {
		fmt.Printf("  \033[0;35mWAF Detected\033[0m:      %s\n", auditResult.WAFDetected)
	}
	if auditResult.ServerInfo != "" {
		fmt.Printf("  \033[0;36mServer\033[0m:            %s\n", auditResult.ServerInfo)
	}

	if len(auditResult.TechFingerprints) > 0 {
		fmt.Printf("  \033[0;36mTechnologies\033[0m:\n")
		for _, fp := range auditResult.TechFingerprints {
			if fp.Version != "" {
				fmt.Printf("    - %s (%s) [%s]\n", fp.Technology, fp.Version, fp.Confidence)
			} else {
				fmt.Printf("    - %s [%s]\n", fp.Technology, fp.Confidence)
			}
		}
	}

	if len(auditResult.MissingHeaders) > 0 {
		fmt.Printf("  \033[0;33mMissing Security Headers\033[0m: (%d)\n", len(auditResult.MissingHeaders))
		for _, mh := range auditResult.MissingHeaders {
			fmt.Printf("    - [%s] %s\n", getSeverityColor(mh.Severity), mh.Header)
			fmt.Printf("      Impact: %s\n", mh.Impact)
			fmt.Printf("      Fix: %s\n", mh.Remediation)
		}
	}

	if len(auditResult.InformationLeaks) > 0 {
		fmt.Printf("  \033[0;33mInformation Leaks\033[0m: (%d)\n", len(auditResult.InformationLeaks))
		for _, leak := range auditResult.InformationLeaks {
			fmt.Printf("    - [%s] %s: %s = %s\n",
				getSeverityColor(leak.Severity), leak.Type, leak.Header, leak.Value)
		}
	}

	if auditResult.CORSAnalysis != nil {
		fmt.Printf("  \033[0;36mCORS Configuration\033[0m:\n")
		fmt.Printf("    Allow-Origin: %s\n", auditResult.CORSAnalysis.AllowOrigin)
		fmt.Printf("    Allow-Credentials: %v\n", auditResult.CORSAnalysis.AllowCredentials)
		if auditResult.CORSAnalysis.Vulnerable {
			fmt.Printf("    \033[0;31mVULNERABLE: %s\033[0m\n", auditResult.CORSAnalysis.Details)
		}
	}

	fmt.Println("\033[0;33m" + strings.Repeat("\u2500", 60) + "\033[0m")
}

func getSeverityColor(severity string) string {
	switch severity {
	case "Critical":
		return fmt.Sprintf("\033[1;31m%s\033[0m", severity)
	case "High":
		return fmt.Sprintf("\033[0;31m%s\033[0m", severity)
	case "Medium":
		return fmt.Sprintf("\033[0;33m%s\033[0m", severity)
	case "Low":
		return fmt.Sprintf("\033[0;32m%s\033[0m", severity)
	default:
		return fmt.Sprintf("\033[0;34m%s\033[0m", severity)
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

type progressReader struct {
	reader     io.Reader
	total      int64
	current    int64
	lastUpdate time.Time
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.current += int64(n)

	if time.Since(pr.lastUpdate) > 100*time.Millisecond {
		progress := float64(pr.current) / float64(pr.total)
		barWidth := 20
		filled := int(progress * float64(barWidth))

		bar := strings.Repeat("#", filled) + strings.Repeat(" ", barWidth-filled)
		percentage := int(progress * 100)

		currentMB := float64(pr.current) / (1024 * 1024)
		totalMB := float64(pr.total) / (1024 * 1024)

		fmt.Printf("\r\033[0;34m[INFO]\033[0m Downloading [%s] %d%% (%.1f/%.1f MB)",
			bar, percentage, currentMB, totalMB)
		pr.lastUpdate = time.Now()
	}

	return n, err
}

func updateTool() {
	fmt.Printf("\033[0;34m[INFO]\033[0m Checking for updates...\n")

	resp, err := http.Get("https://api.github.com/repos/cc1a2b/HHunter/releases/latest")
	if err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to check for updates: %v\n", err)
		fmt.Printf("\033[0;33m[INFO]\033[0m You can manually update from: https://github.com/cc1a2b/HHunter/releases\n")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to fetch release information\n")
		fmt.Printf("\033[0;33m[INFO]\033[0m You can manually update from: https://github.com/cc1a2b/HHunter/releases\n")
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to read response: %v\n", err)
		return
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.Unmarshal(body, &release); err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to parse release information: %v\n", err)
		return
	}

	if release.TagName == version {
		fmt.Printf("\033[0;32m[INFO]\033[0m You are already running the latest version: %s\n", version)
		return
	}

	fmt.Printf("\033[0;33m[INFO]\033[0m New version available: %s (current: %s)\n", release.TagName, version)

	var downloadURL string
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	for _, asset := range release.Assets {
		if strings.Contains(asset.Name, goos) && strings.Contains(asset.Name, goarch) {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		fmt.Printf("\033[0;31m[ERROR]\033[0m No suitable binary found for your platform (%s_%s)\n", goos, goarch)
		fmt.Printf("\033[0;33m[INFO]\033[0m Please download manually from: https://github.com/cc1a2b/HHunter/releases/tag/%s\n", release.TagName)
		return
	}

	resp, err = http.Get(downloadURL)
	if err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to download update: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to download update (status: %d)\n", resp.StatusCode)
		return
	}

	contentLength := resp.ContentLength
	var binaryData []byte

	if contentLength > 0 {
		reader := &progressReader{
			reader: resp.Body,
			total:  contentLength,
		}
		binaryData, err = io.ReadAll(reader)
		fmt.Println()
	} else {
		binaryData, err = io.ReadAll(resp.Body)
	}

	if err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to read binary data: %v\n", err)
		return
	}

	// Extract binary from archive
	var extractedBinary []byte
	if strings.HasSuffix(downloadURL, ".tar.gz") || strings.HasSuffix(downloadURL, ".tgz") {
		extractedBinary, err = extractFromTarGz(binaryData, "hhunter")
	} else if strings.HasSuffix(downloadURL, ".zip") {
		extractedBinary, err = extractFromZip(binaryData, "hhunter")
	} else {
		extractedBinary = binaryData
	}

	if err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to extract binary from archive: %v\n", err)
		return
	}

	currentPath, err := os.Executable()
	if err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to get current executable path: %v\n", err)
		return
	}

	backupPath := currentPath + ".backup"
	if err := os.Rename(currentPath, backupPath); err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to create backup: %v\n", err)
		return
	}

	if err := os.WriteFile(currentPath, extractedBinary, 0755); err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to write new binary: %v\n", err)
		os.Rename(backupPath, currentPath)
		return
	}

	os.Remove(backupPath)

	fmt.Printf("\033[0;32m[SUCCESS]\033[0m Successfully updated to %s!\n", release.TagName)
	fmt.Printf("\033[0;34m[INFO]\033[0m Restart the tool to use the new version.\n")
}

func extractFromTarGz(data []byte, binaryName string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip open: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar read: %w", err)
		}
		name := hdr.Name
		// Strip directory prefix if present
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		// Match: hhunter, hhunter-linux-amd64, etc.
		if name == binaryName || strings.HasPrefix(name, binaryName+"-") {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("binary %q not found in archive", binaryName)
}

func extractFromZip(data []byte, binaryName string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("zip open: %w", err)
	}

	for _, f := range zr.File {
		name := f.Name
		// Strip directory prefix if present
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		// Match: hhunter.exe, hhunter-windows-amd64.exe, etc.
		if name == binaryName || name == binaryName+".exe" ||
			strings.HasPrefix(name, binaryName+"-") {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("binary %q not found in archive", binaryName)
}

func saveResults(result *engine.ScanResult, filename string) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to marshal results: %v\n", err)
		return
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to write output file: %v\n", err)
		return
	}

	fmt.Printf("\033[0;32m[SUCCESS]\033[0m Results saved to: %s\n", filename)
}

func saveMultiResults(results []*engine.ScanResult, filename string) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to marshal results: %v\n", err)
		return
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to write output file: %v\n", err)
		return
	}

	fmt.Printf("\033[0;32m[SUCCESS]\033[0m Results saved to: %s (%d targets)\n", filename, len(results))
}
