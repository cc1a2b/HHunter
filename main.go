package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/cc1a2b/jshunter/engine"
	"github.com/cc1a2b/jshunter/headers"
)

var version = "v1.0"

type arrayFlags []string

func (i *arrayFlags) String() string {
	return strings.Join(*i, ", ")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var (
	url          string
	method       string
	auth         bool
	proxy        bool
	cors         bool
	cache        bool
	override     bool
	cloud        bool
	debug        bool
	chain        bool
	diffOnly     bool
	privCheck    bool
	wafEvasion   bool
	stealth      bool
	proxyURL     string
	output       string
	workers      int
	rateLimit    int
	timeout      int
	customHeader arrayFlags
	showHelp     bool
	update       bool
	quiet        bool
)

func init() {
	engine.GetAuthMutations = headers.GetAuthMutations
	engine.GetProxyMutations = headers.GetProxyMutations
	engine.GetCORSMutations = headers.GetCORSMutations
	engine.GetCacheMutations = headers.GetCacheMutations
	engine.GetOverrideMutations = headers.GetOverrideMutations
	engine.GetCloudMutations = headers.GetCloudMutations
	engine.GetDebugMutations = headers.GetDebugMutations
}

func main() {
	flag.StringVar(&url, "u", "", "Target URL (required)")
	flag.StringVar(&url, "url", "", "Target URL (required)")
	flag.StringVar(&method, "m", "GET", "HTTP method")
	flag.StringVar(&method, "method", "GET", "HTTP method")
	flag.BoolVar(&auth, "auth", false, "Test auth headers")
	flag.BoolVar(&proxy, "proxy", false, "Test proxy headers")
	flag.BoolVar(&cors, "cors", false, "Test CORS headers")
	flag.BoolVar(&cache, "cache", false, "Test cache headers")
	flag.BoolVar(&override, "override", false, "Test method override headers")
	flag.BoolVar(&cloud, "cloud", false, "Test cloud/CDN headers")
	flag.BoolVar(&debug, "debug", false, "Test debug headers")
	flag.BoolVar(&chain, "chain", false, "Chain multiple header mutations")
	flag.BoolVar(&diffOnly, "diff-only", false, "Only show significant differences")
	flag.BoolVar(&privCheck, "priv-check", false, "Check for privilege escalation")
	flag.BoolVar(&wafEvasion, "waf-evasion", false, "Enable WAF evasion techniques")
	flag.BoolVar(&stealth, "stealth", false, "Stealth mode (slower, more evasive)")
	flag.StringVar(&proxyURL, "proxy-url", "", "HTTP proxy URL")
	flag.StringVar(&output, "o", "", "Output file (JSON)")
	flag.StringVar(&output, "output", "", "Output file (JSON)")
	flag.IntVar(&workers, "w", 30, "Number of concurrent workers")
	flag.IntVar(&workers, "workers", 30, "Number of concurrent workers")
	flag.IntVar(&rateLimit, "r", 0, "Rate limit in ms between requests")
	flag.IntVar(&rateLimit, "rate", 0, "Rate limit in ms between requests")
	flag.IntVar(&timeout, "t", 30, "Request timeout in seconds")
	flag.IntVar(&timeout, "timeout", 30, "Request timeout in seconds")
	flag.Var(&customHeader, "H", "Custom header (can be used multiple times)")
	flag.Var(&customHeader, "header", "Custom header (can be used multiple times)")
	flag.BoolVar(&showHelp, "h", false, "Show help")
	flag.BoolVar(&showHelp, "help", false, "Show help")
	flag.BoolVar(&update, "update", false, "Update to latest version")
	flag.BoolVar(&update, "up", false, "Update to latest version")
	flag.BoolVar(&quiet, "q", false, "Quiet mode: suppress banner")
	flag.BoolVar(&quiet, "quiet", false, "Quiet mode: suppress banner")

	flag.Parse()

	if showHelp || url == "" {
		printBanner()
		printHelp()
		os.Exit(0)
	}

	if update {
		updateTool()
		return
	}

	if !quiet {
		printBanner()
	}

	if !auth && !proxy && !cors && !cache && !override && !cloud && !debug {
		fmt.Println("[!] No test categories specified. Running all tests...")
		auth = true
		proxy = true
		cors = true
		cache = true
		override = true
		cloud = true
		debug = true
	}

	headerMap := make(map[string]string)
	for _, h := range customHeader {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	config := &engine.ScanConfig{
		URL:        url,
		Method:     method,
		Headers:    headerMap,
		Auth:       auth,
		Proxy:      proxy,
		CORS:       cors,
		Cache:      cache,
		Override:   override,
		Cloud:      cloud,
		Debug:      debug,
		Chain:      chain,
		DiffOnly:   diffOnly,
		PrivCheck:  privCheck,
		WAFEvasion: wafEvasion,
		ProxyURL:   proxyURL,
		Workers:    workers,
		RateLimit:  rateLimit,
		Stealth:    stealth,
		Timeout:    time.Duration(timeout) * time.Second,
	}

	orchestrator := engine.NewOrchestrator(config)

	findings, err := orchestrator.Scan()
	if err != nil {
		fmt.Printf("\033[31m[!] Scan failed: %v\033[0m\n", err)
		os.Exit(1)
	}

	printFindings(findings)

	if output != "" {
		saveFindings(findings, output)
	}
}

func printBanner() {
	versionStatus := getVersionStatus()
	var statusColor string
	var statusText string

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

 %s (%s%s%s)                         Created by cc1a2b

`, version, statusColor, statusText, "\033[0m")
}

func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("  -u, --url URL                 Input a target URL")
	fmt.Println()

	fmt.Println("Basic Options:")
	fmt.Println("  -m, --method METHOD           HTTP method (default: GET)")
	fmt.Println("  -w, --workers INT             Number of concurrent workers (default: 30)")
	fmt.Println("  -r, --rate MS                 Rate limit delay in milliseconds")
	fmt.Println("  -t, --timeout SEC             Request timeout in seconds (default: 30)")
	fmt.Println("  -k, --skip-tls                Skip TLS certificate verification")
	fmt.Println("  -o, --output FILE.json        Output file path (JSON format)")
	fmt.Println("  -q, --quiet                   Quiet mode: suppress banner")
	fmt.Println("  --update, --up                Update to latest version")
	fmt.Println("  -h, --help                    Display this help message")
	fmt.Println()

	fmt.Println("HTTP Configuration:")
	fmt.Println("  -H, --header \"Key: Value\"     Custom HTTP headers (repeatable)")
	fmt.Println("  --proxy-url URL               HTTP proxy URL (e.g., http://127.0.0.1:8080)")
	fmt.Println()

	fmt.Println("Header Attack Categories:")
	fmt.Println("  --auth                        Test authentication & authorization bypass")
	fmt.Println("  --proxy                       Test proxy trust headers (X-Forwarded-For, etc)")
	fmt.Println("  --cors                        Test CORS misconfigurations")
	fmt.Println("  --cache                       Test cache poisoning vulnerabilities")
	fmt.Println("  --override                    Test HTTP method override attacks")
	fmt.Println("  --cloud                       Test cloud/CDN header injections")
	fmt.Println("  --debug                       Test debug header exposure")
	fmt.Println()

	fmt.Println("Advanced Options:")
	fmt.Println("  --diff-only                   Only show significant response differences")
	fmt.Println("  --priv-check                  Enable privilege escalation detection")
	fmt.Println("  --waf-evasion                 Enable WAF bypass techniques")
	fmt.Println("  --stealth                     Stealth mode (slower, more evasive)")
	fmt.Println("  --chain                       Chain multiple header mutations")
	fmt.Println()

	fmt.Println("Examples:")
	fmt.Println("  # Basic auth bypass test")
	fmt.Println("  hhunter -u https://api.target.com/admin --auth")
	fmt.Println()
	fmt.Println("  # Proxy trust abuse testing")
	fmt.Println("  hhunter -u https://api.target.com/internal --proxy --waf-evasion")
	fmt.Println()
	fmt.Println("  # Full scan with all categories")
	fmt.Println("  hhunter -u https://target.com/api --auth --proxy --cors --cache --override --cloud --debug -o results.json")
	fmt.Println()
	fmt.Println("  # Stealth scan through Burp Suite")
	fmt.Println("  hhunter -u https://target.com --auth --proxy --stealth --proxy-url http://127.0.0.1:8080")
}

func printFindings(findings []engine.Finding) {
	if len(findings) == 0 {
		fmt.Println("\n\033[0;34m[MISSING]\033[0m No vulnerabilities found")
		return
	}

	fmt.Printf("\n\033[0;31m[ FOUND ]\033[0m Discovered %d potential vulnerabilities\n\n", len(findings))

	for i, finding := range findings {
		fmt.Println("\033[0;33m─────────────────────────────────────────\033[0m")
		fmt.Printf("\033[0;31m[!]\033[0m Finding #%d\n", i+1)
		fmt.Printf("  \033[0;36mHeader\033[0m: %s\n", finding.Header)
		fmt.Printf("  \033[0;36mPayload\033[0m: %s\n", finding.Payload)
		fmt.Printf("  \033[0;36mImpact\033[0m: %s\n", finding.Impact)
		fmt.Printf("  \033[0;36mCategory\033[0m: %s\n", finding.Category)
		fmt.Printf("  \033[0;36mSeverity\033[0m: %s\n", getSeverityColor(finding.Severity))
		fmt.Printf("  \033[0;36mConfidence\033[0m: %s\n", finding.Confidence)

		if len(finding.Evidence) > 0 {
			fmt.Printf("  \033[0;36mEvidence\033[0m:\n")
			for k, v := range finding.Evidence {
				fmt.Printf("    - %s: %s\n", k, v)
			}
		}
	}
	fmt.Println("\033[0;33m─────────────────────────────────────────\033[0m")
}

func getSeverityColor(severity string) string {
	switch severity {
	case "Critical":
		return fmt.Sprintf("\033[0;31m%s\033[0m", severity)
	case "High":
		return fmt.Sprintf("\033[0;31m%s\033[0m", severity)
	case "Medium":
		return fmt.Sprintf("\033[0;33m%s\033[0m", severity)
	default:
		return fmt.Sprintf("\033[0;32m%s\033[0m", severity)
	}
}

func getVersionStatus() string {
	currentVersion := version

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/cc1a2b/hhunter/releases/latest")
	if err != nil {
		return "Unknown"
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "Unknown"
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "Unknown"
	}

	var release struct {
		TagName string `json:"tag_name"`
	}

	err = json.Unmarshal(body, &release)
	if err != nil {
		return "Unknown"
	}

	latestVersion := release.TagName

	if latestVersion == currentVersion {
		return "latest"
	}

	return "outdated"
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

	currentVersion := version

	resp, err := http.Get("https://api.github.com/repos/cc1a2b/hhunter/releases/latest")
	if err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to check for updates: %v\n", err)
		fmt.Printf("\033[0;33m[INFO]\033[0m You can manually update from: https://github.com/cc1a2b/hhunter/releases\n")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to fetch release information\n")
		fmt.Printf("\033[0;33m[INFO]\033[0m You can manually update from: https://github.com/cc1a2b/hhunter/releases\n")
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
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

	err = json.Unmarshal(body, &release)
	if err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to parse release information: %v\n", err)
		return
	}

	latestVersion := release.TagName

	if latestVersion == currentVersion {
		fmt.Printf("\033[0;32m[INFO]\033[0m You are already running the latest version: %s\n", currentVersion)
		return
	}

	fmt.Printf("\033[0;33m[INFO]\033[0m New version available: %s (current: %s)\n", latestVersion, currentVersion)

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
		for _, asset := range release.Assets {
			if asset.Name == "hhunter" || strings.HasPrefix(asset.Name, "hhunter") {
				downloadURL = asset.BrowserDownloadURL
				break
			}
		}
	}

	if downloadURL == "" {
		fmt.Printf("\033[0;31m[ERROR]\033[0m No suitable binary found for your platform (%s_%s)\n", goos, goarch)
		fmt.Printf("\033[0;33m[INFO]\033[0m Please download manually from: https://github.com/cc1a2b/hhunter/releases/tag/%s\n", latestVersion)
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

		binaryData, err = ioutil.ReadAll(reader)

		if err == nil {
			progress := float64(reader.total) / float64(reader.total)
			barWidth := 20
			filled := int(progress * float64(barWidth))
			bar := strings.Repeat("#", filled) + strings.Repeat(" ", barWidth-filled)
			percentage := int(progress * 100)
			currentMB := float64(reader.total) / (1024 * 1024)
			totalMB := float64(reader.total) / (1024 * 1024)

			fmt.Printf("\r\033[0;34m[INFO]\033[0m Downloading [%s] %d%% (%.1f/%.1f MB)\n",
				bar, percentage, currentMB, totalMB)
		} else {
			fmt.Println()
		}
	} else {
		binaryData, err = ioutil.ReadAll(resp.Body)
	}

	if err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to read binary data: %v\n", err)
		return
	}

	currentPath, err := os.Executable()
	if err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to get current executable path: %v\n", err)
		return
	}

	backupPath := currentPath + ".backup"
	err = os.Rename(currentPath, backupPath)
	if err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to create backup: %v\n", err)
		return
	}

	err = ioutil.WriteFile(currentPath, binaryData, 0755)
	if err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to write new binary: %v\n", err)
		os.Rename(backupPath, currentPath)
		return
	}

	os.Remove(backupPath)

	fmt.Printf("\033[0;32m[SUCCESS]\033[0m Successfully updated to %s!\n", latestVersion)
	fmt.Printf("\033[0;34m[INFO]\033[0m Restart the tool to use the new version.\n")
}

func saveFindings(findings []engine.Finding, filename string) {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to marshal findings: %v\n", err)
		return
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Printf("\033[0;31m[ERROR]\033[0m Failed to write output file: %v\n", err)
		return
	}

	fmt.Printf("\033[0;32m[SUCCESS]\033[0m Results saved to: %s\n", filename)
}
