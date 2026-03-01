package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cc1a2b/HHunter/engine"
	"github.com/cc1a2b/HHunter/headers"
)

func main() {
	// Register mutation functions
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

	// Configure scan
	config := &engine.ScanConfig{
		URL:        "https://httpbin.org/headers",
		Method:     "GET",
		Headers:    make(map[string]string),
		Auth:       true,
		Proxy:      true,
		CORS:       false,
		Cache:      false,
		Override:   false,
		Cloud:      false,
		Debug:      false,
		Smuggling:  false,
		Injection:  false,
		SSRF:       false,
		HopByHop:   false,
		RateLimit:  false,
		Security:   false,
		WebSocket:  false,
		JWT:        false,
		Chain:      false,
		DiffOnly:   true,
		PrivCheck:  true,
		WAFEvasion: false,
		Audit:      true,
		ProxyURL:   "",
		Workers:    30,
		RateDelay:  100,
		Stealth:    false,
		Timeout:    30 * time.Second,
	}

	// Create orchestrator
	orchestrator := engine.NewOrchestrator(config)

	// Run scan
	fmt.Println("Starting HHunter scan...")
	result, err := orchestrator.Scan()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Display results
	fmt.Printf("\nFound %d potential vulnerabilities:\n\n", len(result.Findings))

	for i, finding := range result.Findings {
		fmt.Printf("Finding #%d:\n", i+1)
		fmt.Printf("  Header: %s\n", finding.Header)
		fmt.Printf("  Payload: %s\n", finding.Payload)
		fmt.Printf("  Impact: %s\n", finding.Impact)
		fmt.Printf("  Severity: %s\n", finding.Severity)
		fmt.Printf("  Confidence: %s\n", finding.Confidence)
		if finding.CWE != "" {
			fmt.Printf("  CWE: %s\n", finding.CWE)
		}
		if finding.CVSS > 0 {
			fmt.Printf("  CVSS: %.1f\n", finding.CVSS)
		}

		if len(finding.Evidence) > 0 {
			fmt.Println("  Evidence:")
			for k, v := range finding.Evidence {
				fmt.Printf("    %s: %s\n", k, v)
			}
		}
		fmt.Println()
	}

	// Display stats
	fmt.Printf("Stats: %d critical, %d high, %d medium, %d low, %d info\n",
		result.Stats.Critical, result.Stats.High, result.Stats.Medium,
		result.Stats.Low, result.Stats.Info)

	// Save to JSON
	data, _ := json.MarshalIndent(result, "", "  ")
	os.WriteFile("scan_results.json", data, 0644)
	fmt.Println("Results saved to scan_results.json")
}
