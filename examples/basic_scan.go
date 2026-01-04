package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cc1a2b/jshunter/engine"
	"github.com/cc1a2b/jshunter/headers"
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
		Chain:      false,
		DiffOnly:   true,
		PrivCheck:  true,
		WAFEvasion: false,
		ProxyURL:   "",
		Workers:    30,
		RateLimit:  100,
		Stealth:    false,
		Timeout:    30 * time.Second,
	}

	// Create orchestrator
	orchestrator := engine.NewOrchestrator(config)

	// Run scan
	fmt.Println("Starting HHunter scan...")
	findings, err := orchestrator.Scan()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Display results
	fmt.Printf("\nFound %d potential vulnerabilities:\n\n", len(findings))

	for i, finding := range findings {
		fmt.Printf("Finding #%d:\n", i+1)
		fmt.Printf("  Header: %s\n", finding.Header)
		fmt.Printf("  Payload: %s\n", finding.Payload)
		fmt.Printf("  Impact: %s\n", finding.Impact)
		fmt.Printf("  Severity: %s\n", finding.Severity)
		fmt.Printf("  Confidence: %s\n", finding.Confidence)

		if len(finding.Evidence) > 0 {
			fmt.Println("  Evidence:")
			for k, v := range finding.Evidence {
				fmt.Printf("    %s: %s\n", k, v)
			}
		}
		fmt.Println()
	}

	// Save to JSON
	data, _ := json.MarshalIndent(findings, "", "  ")
	os.WriteFile("scan_results.json", data, 0644)
	fmt.Println("Results saved to scan_results.json")
}
