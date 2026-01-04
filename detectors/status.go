package detectors

import "github.com/cc1a2b/jshunter/engine"

type StatusDetector struct{}

func NewStatusDetector() *StatusDetector {
	return &StatusDetector{}
}

func (d *StatusDetector) Detect(baseline, mutated *engine.ResponseContext) bool {
	if baseline.StatusCode == 401 && mutated.StatusCode == 200 {
		return true
	}
	if baseline.StatusCode == 403 && mutated.StatusCode == 200 {
		return true
	}
	if baseline.StatusCode >= 400 && mutated.StatusCode < 400 {
		return true
	}
	if baseline.StatusCode == 404 && mutated.StatusCode == 200 {
		return true
	}
	if baseline.StatusCode == 302 && mutated.StatusCode == 200 {
		return true
	}
	return false
}

func (d *StatusDetector) CalculateSeverity(baseline, mutated *engine.ResponseContext) string {
	if baseline.StatusCode == 401 && mutated.StatusCode == 200 {
		return "Critical"
	}
	if baseline.StatusCode == 403 && mutated.StatusCode == 200 {
		return "Critical"
	}
	if baseline.StatusCode >= 400 && mutated.StatusCode < 400 {
		return "High"
	}
	return "Medium"
}

func (d *StatusDetector) GetEvidence(baseline, mutated *engine.ResponseContext) map[string]string {
	evidence := make(map[string]string)
	if baseline.StatusCode != mutated.StatusCode {
		evidence["status_transition"] = string(rune(baseline.StatusCode)) + " -> " + string(rune(mutated.StatusCode))
	}
	return evidence
}
