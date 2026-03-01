package engine

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"strings"
	"time"
)

// GenerateHTMLReport creates a professional, self-contained HTML report
func GenerateHTMLReport(result *ScanResult, targetURL string, filename string) error {
	report := buildHTMLReport(result, targetURL)
	return os.WriteFile(filename, []byte(report), 0644)
}

// GenerateSARIF creates a SARIF 2.1.0 report for CI/CD integration
func GenerateSARIF(result *ScanResult, targetURL string, filename string) error {
	sarif := buildSARIF(result, targetURL)
	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return fmt.Errorf("sarif marshal failed: %w", err)
	}
	return os.WriteFile(filename, data, 0644)
}

func buildHTMLReport(result *ScanResult, targetURL string) string {
	var sb strings.Builder

	criticalCount := result.Stats.Critical
	highCount := result.Stats.High
	mediumCount := result.Stats.Medium
	lowCount := result.Stats.Low
	infoCount := result.Stats.Info
	totalFindings := result.Stats.TotalFindings

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HHunter Security Report</title>
<style>
:root {
  --bg: #0a0e17;
  --card: #111827;
  --border: #1f2937;
  --text: #e5e7eb;
  --text-muted: #9ca3af;
  --critical: #ef4444;
  --high: #f97316;
  --medium: #eab308;
  --low: #22c55e;
  --info: #3b82f6;
  --accent: #8b5cf6;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace; background: var(--bg); color: var(--text); line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
.header { text-align: center; margin-bottom: 3rem; padding: 2rem; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); border-radius: 12px; border: 1px solid var(--border); }
.header h1 { font-size: 2.5rem; color: #fff; margin-bottom: 0.5rem; }
.header .subtitle { color: var(--text-muted); font-size: 0.9rem; }
.header .target { color: var(--accent); font-size: 1.1rem; margin-top: 0.5rem; word-break: break-all; }
.meta { display: flex; justify-content: center; gap: 2rem; margin-top: 1rem; color: var(--text-muted); font-size: 0.85rem; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
.stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; text-align: center; }
.stat-card .value { font-size: 2.5rem; font-weight: bold; }
.stat-card .label { color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.1em; }
.stat-critical .value { color: var(--critical); }
.stat-high .value { color: var(--high); }
.stat-medium .value { color: var(--medium); }
.stat-low .value { color: var(--low); }
.stat-info .value { color: var(--info); }
.stat-total .value { color: var(--accent); }
.section-title { font-size: 1.3rem; color: #fff; margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid var(--accent); }
.finding { background: var(--card); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
.finding-header { display: flex; justify-content: space-between; align-items: center; padding: 1rem 1.5rem; cursor: pointer; }
.finding-header:hover { background: rgba(255,255,255,0.03); }
.finding-title { font-weight: bold; font-size: 1rem; }
.badge { padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }
.badge-critical { background: rgba(239,68,68,0.2); color: var(--critical); border: 1px solid var(--critical); }
.badge-high { background: rgba(249,115,22,0.2); color: var(--high); border: 1px solid var(--high); }
.badge-medium { background: rgba(234,179,8,0.2); color: var(--medium); border: 1px solid var(--medium); }
.badge-low { background: rgba(34,197,94,0.2); color: var(--low); border: 1px solid var(--low); }
.badge-info { background: rgba(59,130,246,0.2); color: var(--info); border: 1px solid var(--info); }
.badge-verified { background: rgba(34,197,94,0.2); color: var(--low); border: 1px solid var(--low); margin-left: 0.5rem; }
.badge-oob { background: rgba(139,92,246,0.2); color: var(--accent); border: 1px solid var(--accent); margin-left: 0.5rem; }
.finding-body { padding: 0 1.5rem 1.5rem; display: none; }
.finding.open .finding-body { display: block; }
.finding-row { display: flex; margin-bottom: 0.5rem; }
.finding-row .label { color: var(--text-muted); min-width: 140px; font-size: 0.85rem; }
.finding-row .value { color: var(--text); word-break: break-all; font-size: 0.85rem; }
.evidence-box { background: #0d1117; border: 1px solid var(--border); border-radius: 4px; padding: 1rem; margin-top: 0.5rem; font-size: 0.8rem; }
.evidence-box .entry { margin-bottom: 0.25rem; }
.evidence-box .key { color: var(--accent); }
.evidence-box .val { color: var(--text-muted); }
.remediation { background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3); border-radius: 4px; padding: 1rem; margin-top: 0.75rem; font-size: 0.85rem; color: var(--low); }
.audit-section { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }
.audit-section h3 { color: #fff; margin-bottom: 1rem; font-size: 1rem; }
.audit-item { margin-bottom: 0.5rem; font-size: 0.85rem; }
.footer { text-align: center; color: var(--text-muted); font-size: 0.8rem; margin-top: 3rem; padding: 1rem; border-top: 1px solid var(--border); }
.toggle-icon { color: var(--text-muted); transition: transform 0.2s; }
.finding.open .toggle-icon { transform: rotate(90deg); }
.confidence-bar { height: 4px; border-radius: 2px; background: var(--border); margin-top: 0.25rem; }
.confidence-fill { height: 100%; border-radius: 2px; }
</style>
</head>
<body>
<div class="container">
`)

	// Header
	sb.WriteString(fmt.Sprintf(`
<div class="header">
  <h1>HHunter</h1>
  <div class="subtitle">HTTP Header Security Assessment Report</div>
  <div class="target">%s</div>
  <div class="meta">
    <span>Generated: %s</span>
    <span>Duration: %s</span>
    <span>Mutations: %d</span>
    <span>Version: v4.0</span>
  </div>
</div>
`, html.EscapeString(targetURL),
		time.Now().Format("2006-01-02 15:04:05 MST"),
		result.Stats.Duration.Round(time.Millisecond).String(),
		result.Stats.TotalMutations))

	// Stats grid
	sb.WriteString(`<div class="stats-grid">`)
	sb.WriteString(fmt.Sprintf(`<div class="stat-card stat-total"><div class="value">%d</div><div class="label">Total Findings</div></div>`, totalFindings))
	sb.WriteString(fmt.Sprintf(`<div class="stat-card stat-critical"><div class="value">%d</div><div class="label">Critical</div></div>`, criticalCount))
	sb.WriteString(fmt.Sprintf(`<div class="stat-card stat-high"><div class="value">%d</div><div class="label">High</div></div>`, highCount))
	sb.WriteString(fmt.Sprintf(`<div class="stat-card stat-medium"><div class="value">%d</div><div class="label">Medium</div></div>`, mediumCount))
	sb.WriteString(fmt.Sprintf(`<div class="stat-card stat-low"><div class="value">%d</div><div class="label">Low</div></div>`, lowCount))
	sb.WriteString(fmt.Sprintf(`<div class="stat-card stat-info"><div class="value">%d</div><div class="label">Info</div></div>`, infoCount))
	sb.WriteString(`</div>`)

	// Findings
	if len(result.Findings) > 0 {
		sb.WriteString(`<div class="section-title">Findings</div>`)

		for i, f := range result.Findings {
			badgeClass := "badge-" + strings.ToLower(f.Severity)
			extraBadges := ""
			if f.Verified {
				extraBadges += `<span class="badge badge-verified">VERIFIED</span>`
			}
			if f.Evidence["oob_confirmed"] == "true" {
				extraBadges += `<span class="badge badge-oob">OOB CONFIRMED</span>`
			}

			confidenceColor := "var(--info)"
			if f.ConfidenceScore >= 0.8 {
				confidenceColor = "var(--low)"
			} else if f.ConfidenceScore >= 0.6 {
				confidenceColor = "var(--medium)"
			}

			sb.WriteString(fmt.Sprintf(`
<div class="finding" id="finding-%d">
  <div class="finding-header" onclick="this.parentElement.classList.toggle('open')">
    <div>
      <span class="toggle-icon">&#9654;</span>
      <span class="finding-title">#%d — %s</span>
      %s
    </div>
    <span class="badge %s">%s</span>
  </div>
  <div class="finding-body">
`, i, i+1, html.EscapeString(f.Impact), extraBadges, badgeClass, f.Severity))

			// Details
			sb.WriteString(fmt.Sprintf(`<div class="finding-row"><div class="label">Header</div><div class="value">%s</div></div>`, html.EscapeString(f.Header)))
			sb.WriteString(fmt.Sprintf(`<div class="finding-row"><div class="label">Payload</div><div class="value"><code>%s</code></div></div>`, html.EscapeString(f.Payload)))
			sb.WriteString(fmt.Sprintf(`<div class="finding-row"><div class="label">Category</div><div class="value">%s</div></div>`, html.EscapeString(f.Category)))
			sb.WriteString(fmt.Sprintf(`<div class="finding-row"><div class="label">Confidence</div><div class="value">%s (%.0f%%)</div></div>`, f.Confidence, f.ConfidenceScore*100))

			sb.WriteString(fmt.Sprintf(`<div class="confidence-bar"><div class="confidence-fill" style="width: %.0f%%; background: %s;"></div></div>`, f.ConfidenceScore*100, confidenceColor))

			if f.CVSS > 0 {
				sb.WriteString(fmt.Sprintf(`<div class="finding-row"><div class="label">CVSS</div><div class="value">%.1f</div></div>`, f.CVSS))
			}
			if f.CWE != "" {
				sb.WriteString(fmt.Sprintf(`<div class="finding-row"><div class="label">CWE</div><div class="value">%s</div></div>`, html.EscapeString(f.CWE)))
			}

			// Evidence
			if len(f.Evidence) > 0 {
				sb.WriteString(`<div class="finding-row"><div class="label">Evidence</div><div class="value">`)
				sb.WriteString(`<div class="evidence-box">`)
				for k, v := range f.Evidence {
					sb.WriteString(fmt.Sprintf(`<div class="entry"><span class="key">%s</span>: <span class="val">%s</span></div>`,
						html.EscapeString(k), html.EscapeString(v)))
				}
				sb.WriteString(`</div></div></div>`)
			}

			// Remediation
			if f.Remediation != "" {
				sb.WriteString(fmt.Sprintf(`<div class="remediation">%s</div>`, html.EscapeString(f.Remediation)))
			}

			sb.WriteString(`</div></div>`)
		}
	} else {
		sb.WriteString(`<div class="section-title">No vulnerabilities found</div>`)
	}

	// Security Audit
	if result.SecurityAudit != nil {
		sb.WriteString(`<div class="section-title">Security Audit</div>`)

		audit := result.SecurityAudit

		if audit.WAFDetected != "" {
			sb.WriteString(fmt.Sprintf(`<div class="audit-section"><h3>WAF Detected</h3><div class="audit-item">%s</div></div>`, html.EscapeString(audit.WAFDetected)))
		}

		if len(audit.TechFingerprints) > 0 {
			sb.WriteString(`<div class="audit-section"><h3>Technology Fingerprints</h3>`)
			for _, fp := range audit.TechFingerprints {
				version := ""
				if fp.Version != "" {
					version = " (" + fp.Version + ")"
				}
				sb.WriteString(fmt.Sprintf(`<div class="audit-item">%s%s [%s]</div>`,
					html.EscapeString(fp.Technology), html.EscapeString(version), html.EscapeString(fp.Confidence)))
			}
			sb.WriteString(`</div>`)
		}

		if len(audit.MissingHeaders) > 0 {
			sb.WriteString(`<div class="audit-section"><h3>Missing Security Headers</h3>`)
			for _, mh := range audit.MissingHeaders {
				badgeClass := "badge-" + strings.ToLower(mh.Severity)
				sb.WriteString(fmt.Sprintf(`<div class="audit-item"><span class="badge %s">%s</span> %s — %s</div>`,
					badgeClass, mh.Severity, html.EscapeString(mh.Header), html.EscapeString(mh.Impact)))
			}
			sb.WriteString(`</div>`)
		}

		if len(audit.InformationLeaks) > 0 {
			sb.WriteString(`<div class="audit-section"><h3>Information Leaks</h3>`)
			for _, leak := range audit.InformationLeaks {
				sb.WriteString(fmt.Sprintf(`<div class="audit-item">[%s] %s: %s = %s</div>`,
					html.EscapeString(leak.Severity), html.EscapeString(leak.Type),
					html.EscapeString(leak.Header), html.EscapeString(leak.Value)))
			}
			sb.WriteString(`</div>`)
		}
	}

	// Recon
	if result.Recon != nil {
		sb.WriteString(`<div class="section-title">Reconnaissance</div>`)
		sb.WriteString(`<div class="audit-section">`)
		if len(result.Recon.ReflectedHeaders) > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="audit-item"><strong>Reflected Headers:</strong> %s</div>`,
				html.EscapeString(strings.Join(result.Recon.ReflectedHeaders, ", "))))
		}
		if len(result.Recon.AllowedMethods) > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="audit-item"><strong>Allowed Methods:</strong> %s</div>`,
				html.EscapeString(strings.Join(result.Recon.AllowedMethods, ", "))))
		}
		if len(result.Recon.DangerousMethods) > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="audit-item" style="color:var(--critical)"><strong>Dangerous Methods:</strong> %s</div>`,
				html.EscapeString(strings.Join(result.Recon.DangerousMethods, ", "))))
		}
		if result.Recon.VerbTamperBypasses > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="audit-item" style="color:var(--critical)"><strong>Verb Tamper Bypasses:</strong> %d</div>`, result.Recon.VerbTamperBypasses))
		}
		if len(result.Recon.HostInjectable) > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="audit-item" style="color:var(--high)"><strong>Host Injectable:</strong> %s</div>`,
				html.EscapeString(strings.Join(result.Recon.HostInjectable, ", "))))
		}
		sb.WriteString(`</div>`)
	}

	// Footer
	sb.WriteString(fmt.Sprintf(`
<div class="footer">
  Generated by HHunter v4.0 — HTTP Header Security Testing Engine<br>
  Created by cc1a2b | %s
</div>
</div>

<script>
// Auto-open critical and high findings
document.querySelectorAll('.finding').forEach(el => {
  const badge = el.querySelector('.badge');
  if (badge && (badge.textContent === 'Critical' || badge.textContent === 'High')) {
    el.classList.add('open');
  }
});
</script>
</body>
</html>`, time.Now().Format("2006-01-02")))

	return sb.String()
}

// SARIF types
type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription sarifMessage     `json:"shortDescription"`
	HelpURI          string           `json:"helpUri,omitempty"`
	Properties       sarifProperties  `json:"properties,omitempty"`
}

type sarifProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID    string         `json:"ruleId"`
	Level     string         `json:"level"`
	Message   sarifMessage   `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation  `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

func buildSARIF(result *ScanResult, targetURL string) *sarifReport {
	rules := make(map[string]sarifRule)
	var results []sarifResult

	for _, f := range result.Findings {
		ruleID := f.CWE
		if ruleID == "" {
			ruleID = "HH-" + strings.ReplaceAll(f.Category, " ", "-")
		}

		if _, exists := rules[ruleID]; !exists {
			rules[ruleID] = sarifRule{
				ID:   ruleID,
				Name: f.Category,
				ShortDescription: sarifMessage{
					Text: f.Impact,
				},
			}
		}

		level := "note"
		switch f.Severity {
		case "Critical", "High":
			level = "error"
		case "Medium":
			level = "warning"
		}

		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   level,
			Message: sarifMessage{Text: fmt.Sprintf("[%s] %s: %s -> %s", f.Severity, f.Header, f.Payload, f.Impact)},
			Locations: []sarifLocation{
				{
					PhysicalLocation: &sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: targetURL},
					},
					LogicalLocations: []sarifLogicalLocation{
						{Name: f.Header, Kind: "header"},
					},
				},
			},
			Properties: map[string]interface{}{
				"confidence": f.ConfidenceScore,
				"cvss":       f.CVSS,
				"verified":   f.Verified,
				"category":   f.Category,
			},
		})
	}

	var ruleList []sarifRule
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}

	return &sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "HHunter",
						Version:        "4.0",
						InformationURI: "https://github.com/cc1a2b/HHunter",
						Rules:          ruleList,
					},
				},
				Results: results,
			},
		},
	}
}
