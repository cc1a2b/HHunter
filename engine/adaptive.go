package engine

import (
	"strings"
)

// TechProfile represents the detected technology stack of a target
type TechProfile struct {
	Server     string   // nginx, apache, IIS, etc.
	Language   string   // PHP, Java, Python, .NET, Node.js, etc.
	Framework  string   // Laravel, Spring, Django, Express, etc.
	Cloud      string   // AWS, Azure, GCP, Cloudflare, etc.
	WAF        string   // Cloudflare, AWS WAF, Akamai, etc.
	Technologies []string // All detected technologies
}

// BuildTechProfile constructs a technology profile from security audit results
func BuildTechProfile(audit *SecurityAudit) *TechProfile {
	if audit == nil {
		return nil
	}

	profile := &TechProfile{}

	for _, fp := range audit.TechFingerprints {
		tech := strings.ToLower(fp.Technology)
		profile.Technologies = append(profile.Technologies, fp.Technology)

		// Server detection
		switch {
		case strings.Contains(tech, "nginx"):
			profile.Server = "nginx"
		case strings.Contains(tech, "apache") && !strings.Contains(tech, "tomcat"):
			profile.Server = "apache"
		case strings.Contains(tech, "iis"):
			profile.Server = "iis"
		case strings.Contains(tech, "envoy"):
			profile.Server = "envoy"
		case strings.Contains(tech, "caddy"):
			profile.Server = "caddy"
		case strings.Contains(tech, "tomcat"):
			profile.Server = "tomcat"
			profile.Language = "java"
		case strings.Contains(tech, "jetty"):
			profile.Server = "jetty"
			profile.Language = "java"
		case strings.Contains(tech, "gunicorn") || strings.Contains(tech, "uvicorn"):
			profile.Language = "python"
		case strings.Contains(tech, "kestrel"):
			profile.Language = "dotnet"
		case strings.Contains(tech, "cowboy"):
			profile.Language = "erlang"
		}

		// Language/Framework detection
		switch {
		case strings.Contains(tech, "php"):
			profile.Language = "php"
		case strings.Contains(tech, "asp.net") || strings.Contains(tech, ".net"):
			profile.Language = "dotnet"
		case strings.Contains(tech, "express") || strings.Contains(tech, "next.js") || strings.Contains(tech, "node"):
			profile.Language = "nodejs"
		case strings.Contains(tech, "flask") || strings.Contains(tech, "django"):
			profile.Language = "python"
			profile.Framework = fp.Technology
		case strings.Contains(tech, "spring"):
			profile.Language = "java"
			profile.Framework = "Spring"
		case strings.Contains(tech, "laravel"):
			profile.Language = "php"
			profile.Framework = "Laravel"
		case strings.Contains(tech, "rails"):
			profile.Language = "ruby"
			profile.Framework = "Rails"
		}

		// Cloud detection
		switch {
		case strings.Contains(tech, "cloudflare"):
			profile.Cloud = "cloudflare"
		case strings.Contains(tech, "aws"):
			profile.Cloud = "aws"
		case strings.Contains(tech, "azure"):
			profile.Cloud = "azure"
		}
	}

	profile.WAF = audit.WAFDetected

	return profile
}

// PrioritizeMutationsForTech reorders and augments mutations based on detected technology
func PrioritizeMutationsForTech(mutations []Mutation, tech *TechProfile) []Mutation {
	if tech == nil {
		return mutations
	}

	var highPriority []Mutation
	var normalPriority []Mutation
	var lowPriority []Mutation

	for _, m := range mutations {
		priority := categorizeMutationPriority(m, tech)
		switch priority {
		case "high":
			highPriority = append(highPriority, m)
		case "low":
			lowPriority = append(lowPriority, m)
		default:
			normalPriority = append(normalPriority, m)
		}
	}

	result := make([]Mutation, 0, len(mutations))
	result = append(result, highPriority...)
	result = append(result, normalPriority...)
	result = append(result, lowPriority...)

	return result
}

// categorizeMutationPriority determines if a mutation is high/normal/low priority
// based on the target's technology stack
func categorizeMutationPriority(m Mutation, tech *TechProfile) string {
	impactLower := strings.ToLower(m.Impact)
	valueLower := strings.ToLower(m.Value)
	headerLower := strings.ToLower(m.Header)

	// PHP-specific priorities
	if tech.Language == "php" {
		if strings.Contains(impactLower, "php") || strings.Contains(valueLower, "php") {
			return "high"
		}
		// PHP is vulnerable to CRLF, cookie manipulation
		if m.Category == "CRLF" || m.Category == "Cookie" {
			return "high"
		}
		// PHP debug modes
		if strings.Contains(headerLower, "x-debug") || strings.Contains(valueLower, "xdebug") {
			return "high"
		}
	}

	// Java-specific priorities
	if tech.Language == "java" {
		// Log4Shell is THE Java vulnerability
		if strings.Contains(valueLower, "jndi") || strings.Contains(impactLower, "log4") {
			return "high"
		}
		// Spring-specific
		if tech.Framework == "Spring" {
			if strings.Contains(impactLower, "spring") || strings.Contains(valueLower, "spring") {
				return "high"
			}
			// Spring actuator endpoints via debug headers
			if m.Category == "Debug" {
				return "high"
			}
		}
		// Java deserialization
		if strings.Contains(impactLower, "deserializ") {
			return "high"
		}
		// SSTI for Java template engines
		if strings.Contains(impactLower, "ssti") || strings.Contains(impactLower, "template") {
			return "high"
		}
	}

	// Python-specific priorities
	if tech.Language == "python" {
		// Python SSTI is very common
		if strings.Contains(impactLower, "ssti") || strings.Contains(impactLower, "template") {
			return "high"
		}
		// Debug mode (Werkzeug debugger)
		if m.Category == "Debug" {
			return "high"
		}
	}

	// .NET-specific priorities
	if tech.Language == "dotnet" {
		if strings.Contains(impactLower, "asp.net") || strings.Contains(impactLower, ".net") {
			return "high"
		}
		// .NET debug headers
		if strings.Contains(headerLower, "x-aspnet") {
			return "high"
		}
		// IIS-specific bypasses
		if tech.Server == "iis" {
			if m.Category == "Override" || m.Category == "Auth" {
				return "high"
			}
		}
	}

	// Node.js-specific priorities
	if tech.Language == "nodejs" {
		if strings.Contains(impactLower, "prototype") || strings.Contains(impactLower, "node") {
			return "high"
		}
		// Express.js specific
		if strings.Contains(valueLower, "express") {
			return "high"
		}
		// Node is often vulnerable to SSRF
		if m.Category == "SSRF" {
			return "high"
		}
	}

	// Cloud-specific priorities
	if tech.Cloud != "" {
		// Cloud metadata headers
		if m.Category == "Cloud" {
			return "high"
		}
		// SSRF to cloud metadata
		if m.Category == "SSRF" && (strings.Contains(valueLower, "169.254") || strings.Contains(valueLower, "metadata")) {
			return "high"
		}
	}

	// Cloudflare-specific
	if tech.Cloud == "cloudflare" || tech.WAF == "Cloudflare" {
		// CF-specific headers are high priority against Cloudflare
		if strings.Contains(headerLower, "cf-") {
			return "high"
		}
		// Standard WAF bypass techniques
		if m.Category == "ContentType" || m.Category == "Encoding" {
			return "high"
		}
	}

	// Nginx-specific
	if tech.Server == "nginx" {
		// Nginx path traversal via headers
		if m.Category == "Override" && strings.Contains(headerLower, "x-original-url") {
			return "high"
		}
		// Off-by-slash in Nginx proxy_pass
		if m.Category == "Gateway" {
			return "high"
		}
	}

	// Apache-specific
	if tech.Server == "apache" {
		// Apache mod_rewrite bypass
		if m.Category == "Override" {
			return "high"
		}
		// .htaccess bypass via method
		if m.Category == "Auth" && strings.Contains(impactLower, "method") {
			return "high"
		}
	}

	// WAF-specific: if any WAF detected, prioritize WAF bypass techniques
	if tech.WAF != "" {
		if m.Category == "ContentType" || m.Category == "Encoding" || m.Category == "Gateway" {
			return "high"
		}
	}

	// Lower priority for irrelevant technology combos
	// PHP tech but Java-specific payloads
	if tech.Language == "php" && (strings.Contains(valueLower, "jndi") || strings.Contains(impactLower, "spring")) {
		return "low"
	}
	// Java tech but PHP-specific payloads
	if tech.Language == "java" && (strings.Contains(impactLower, "php") || strings.Contains(valueLower, "xdebug")) {
		return "low"
	}
	// Python tech but .NET-specific payloads
	if tech.Language == "python" && strings.Contains(impactLower, "asp.net") {
		return "low"
	}
	// .NET tech but Python-specific
	if tech.Language == "dotnet" && strings.Contains(impactLower, "werkzeug") {
		return "low"
	}

	return "normal"
}

// GetAdaptiveSummary returns a human-readable summary of adaptive prioritization
func GetAdaptiveSummary(tech *TechProfile) string {
	if tech == nil {
		return "No technology fingerprint available — using default mutation order"
	}

	var parts []string
	if tech.Server != "" {
		parts = append(parts, "Server: "+tech.Server)
	}
	if tech.Language != "" {
		parts = append(parts, "Language: "+tech.Language)
	}
	if tech.Framework != "" {
		parts = append(parts, "Framework: "+tech.Framework)
	}
	if tech.Cloud != "" {
		parts = append(parts, "Cloud: "+tech.Cloud)
	}
	if tech.WAF != "" {
		parts = append(parts, "WAF: "+tech.WAF)
	}

	if len(parts) == 0 {
		return "Minimal fingerprint — using default mutation order"
	}

	return "Adaptive scan targeting: " + strings.Join(parts, " | ")
}
