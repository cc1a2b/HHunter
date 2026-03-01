package engine

import (
	"fmt"
	"sort"
	"strings"
)

// DeduplicateFindings removes duplicate and near-duplicate findings,
// keeping the highest-confidence instance per root cause group.
// Groups are formed by (header_family, impact_type, severity).
func DeduplicateFindings(findings []Finding) []Finding {
	if len(findings) <= 1 {
		return findings
	}

	groups := groupFindings(findings)

	var deduplicated []Finding
	for _, group := range groups {
		best := selectBestFinding(group.findings)
		// Merge evidence from other findings in the group
		best = mergeGroupEvidence(best, group.findings)
		deduplicated = append(deduplicated, best)
	}

	// Sort by severity (Critical > High > Medium > Low > Info), then by confidence
	sort.Slice(deduplicated, func(i, j int) bool {
		si := severityRank(deduplicated[i].Severity)
		sj := severityRank(deduplicated[j].Severity)
		if si != sj {
			return si > sj
		}
		return deduplicated[i].ConfidenceScore > deduplicated[j].ConfidenceScore
	})

	return deduplicated
}

// findingGroup represents a group of related findings
type findingGroup struct {
	key      string
	findings []Finding
}

// groupFindings clusters findings by root cause
func groupFindings(findings []Finding) []findingGroup {
	keyMap := make(map[string][]Finding)
	var keyOrder []string

	for _, f := range findings {
		key := buildGroupKey(f)
		if _, exists := keyMap[key]; !exists {
			keyOrder = append(keyOrder, key)
		}
		keyMap[key] = append(keyMap[key], f)
	}

	groups := make([]findingGroup, 0, len(keyOrder))
	for _, key := range keyOrder {
		groups = append(groups, findingGroup{
			key:      key,
			findings: keyMap[key],
		})
	}
	return groups
}

// buildGroupKey creates a deduplication key for a finding.
// Findings with the same key are considered duplicates/variants.
func buildGroupKey(f Finding) string {
	headerFamily := normalizeHeaderFamily(f.Header)
	impactType := normalizeImpactType(f.Impact, f.Category)

	// OOB-confirmed findings are never grouped with non-OOB
	if f.Evidence["oob_confirmed"] == "true" {
		return headerFamily + "|" + impactType + "|oob"
	}

	// Verified findings are in their own subgroup
	if f.Verified {
		return headerFamily + "|" + impactType + "|verified"
	}

	return headerFamily + "|" + impactType
}

// normalizeHeaderFamily groups related headers into families
func normalizeHeaderFamily(header string) string {
	h := strings.ToLower(header)

	// IP/Proxy headers
	proxyHeaders := []string{
		"x-forwarded-for", "x-real-ip", "x-client-ip", "x-originating-ip",
		"x-remote-ip", "x-remote-addr", "x-cluster-client-ip",
		"cf-connecting-ip", "true-client-ip", "forwarded",
		"x-forwarded-host", "x-forwarded-proto", "x-forwarded-port",
		"x-forwarded-server",
	}
	for _, ph := range proxyHeaders {
		if strings.Contains(h, strings.ToLower(ph)) || h == ph {
			return "proxy_trust"
		}
	}

	// Auth headers
	if strings.Contains(h, "auth") || strings.Contains(h, "bearer") ||
		strings.Contains(h, "token") || strings.Contains(h, "api-key") ||
		strings.Contains(h, "x-user") || strings.Contains(h, "x-role") ||
		strings.Contains(h, "x-admin") {
		return "auth_bypass"
	}

	// Override headers
	if strings.Contains(h, "override") || strings.Contains(h, "x-http-method") ||
		strings.Contains(h, "x-method") || strings.Contains(h, "x-original-url") ||
		strings.Contains(h, "x-rewrite-url") {
		return "method_override"
	}

	// Cache headers
	if strings.Contains(h, "cache") || strings.Contains(h, "x-forwarded-host") ||
		strings.Contains(h, "x-host") {
		return "cache_poison"
	}

	// CORS
	if strings.Contains(h, "origin") || strings.Contains(h, "access-control") {
		return "cors"
	}

	// Debug
	if strings.Contains(h, "debug") || strings.Contains(h, "x-debug") {
		return "debug"
	}

	// Cloud
	if strings.Contains(h, "x-amz") || strings.Contains(h, "x-azure") ||
		strings.Contains(h, "x-goog") || strings.Contains(h, "x-cloud") {
		return "cloud"
	}

	// HTTP Method (recon)
	if h == "http method" {
		return "http_method"
	}

	return h
}

// normalizeImpactType groups similar impact descriptions
func normalizeImpactType(impact, category string) string {
	impactLower := strings.ToLower(impact)

	if strings.Contains(impactLower, "auth") && strings.Contains(impactLower, "bypass") {
		return "auth_bypass"
	}
	if strings.Contains(impactLower, "privilege") || strings.Contains(impactLower, "escalation") {
		return "privilege_escalation"
	}
	if strings.Contains(impactLower, "cors") {
		return "cors_misconfig"
	}
	if strings.Contains(impactLower, "ssrf") {
		return "ssrf"
	}
	if strings.Contains(impactLower, "xss") || strings.Contains(impactLower, "reflection") {
		return "xss_reflection"
	}
	if strings.Contains(impactLower, "cache") && strings.Contains(impactLower, "poison") {
		return "cache_poisoning"
	}
	if strings.Contains(impactLower, "redirect") {
		return "open_redirect"
	}
	if strings.Contains(impactLower, "host") && strings.Contains(impactLower, "inject") {
		return "host_injection"
	}
	if strings.Contains(impactLower, "verb") || strings.Contains(impactLower, "method") {
		return "verb_tamper"
	}
	if strings.Contains(impactLower, "info") || strings.Contains(impactLower, "disclosure") {
		return "info_disclosure"
	}
	if strings.Contains(impactLower, "crlf") || strings.Contains(impactLower, "splitting") {
		return "crlf"
	}
	if strings.Contains(impactLower, "smuggling") {
		return "smuggling"
	}
	if strings.Contains(impactLower, "rate") && strings.Contains(impactLower, "limit") {
		return "rate_limit_bypass"
	}
	if strings.Contains(impactLower, "log4") {
		return "log4shell"
	}
	if strings.Contains(impactLower, "ssti") || strings.Contains(impactLower, "template") {
		return "ssti"
	}
	if strings.Contains(impactLower, "sqli") || strings.Contains(impactLower, "sql") {
		return "sqli"
	}
	if strings.Contains(impactLower, "jwt") {
		return "jwt_attack"
	}

	return strings.ToLower(category)
}

// selectBestFinding picks the highest-quality finding from a group
func selectBestFinding(group []Finding) Finding {
	if len(group) == 1 {
		return group[0]
	}

	best := group[0]
	for _, f := range group[1:] {
		// Prefer verified findings
		if f.Verified && !best.Verified {
			best = f
			continue
		}
		if !f.Verified && best.Verified {
			continue
		}

		// Prefer OOB confirmed
		if f.Evidence["oob_confirmed"] == "true" && best.Evidence["oob_confirmed"] != "true" {
			best = f
			continue
		}

		// Prefer higher confidence
		if f.ConfidenceScore > best.ConfidenceScore {
			best = f
			continue
		}

		// At equal confidence, prefer more evidence
		if f.ConfidenceScore == best.ConfidenceScore && len(f.Evidence) > len(best.Evidence) {
			best = f
		}
	}

	return best
}

// mergeGroupEvidence enriches the best finding with evidence from siblings
func mergeGroupEvidence(best Finding, group []Finding) Finding {
	if len(group) <= 1 {
		return best
	}

	// Collect all unique payloads that trigger this vuln
	var alternatePayloads []string
	for _, f := range group {
		if f.Header == best.Header && f.Payload != best.Payload {
			alternatePayloads = append(alternatePayloads, f.Header+": "+f.Payload)
		} else if f.Header != best.Header {
			alternatePayloads = append(alternatePayloads, f.Header+": "+f.Payload)
		}
	}

	if len(alternatePayloads) > 0 {
		// Cap at 5 alternatives to avoid noise
		if len(alternatePayloads) > 5 {
			alternatePayloads = alternatePayloads[:5]
		}
		best.Evidence["alternate_triggers"] = strings.Join(alternatePayloads, " | ")
		best.Evidence["total_variants"] = strings.Repeat("1", len(group)) // length encodes count
		// Replace with actual count
		best.Evidence["total_variants"] = fmt.Sprintf("%d", len(group))
	}

	return best
}

// severityRank returns a numeric rank for severity sorting
func severityRank(severity string) int {
	switch severity {
	case "Critical":
		return 5
	case "High":
		return 4
	case "Medium":
		return 3
	case "Low":
		return 2
	case "Info":
		return 1
	default:
		return 0
	}
}

