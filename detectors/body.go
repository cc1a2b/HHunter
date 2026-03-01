package detectors

import (
	"encoding/json"
	"strings"

	"github.com/cc1a2b/HHunter/engine"
)

type BodyDetector struct{}

func NewBodyDetector() *BodyDetector {
	return &BodyDetector{}
}

func (d *BodyDetector) Detect(baseline, mutated *engine.ResponseContext) bool {
	if baseline.BodyHash != mutated.BodyHash {
		return true
	}
	return false
}

func (d *BodyDetector) DetectSensitiveData(resp *engine.ResponseContext) []string {
	sensitive := []string{}
	body := strings.ToLower(string(resp.Body))

	patterns := map[string]string{
		"stack_trace":   "at ",
		"sql_error":     "sql",
		"error_detail":  "exception",
		"internal_path": "/var/",
		"api_key":       "api_key",
		"password":      "password",
		"token":         "token",
		"secret":        "secret",
	}

	for name, pattern := range patterns {
		if strings.Contains(body, pattern) {
			sensitive = append(sensitive, name)
		}
	}

	return sensitive
}

func (d *BodyDetector) DetectJSONChanges(baseline, mutated *engine.ResponseContext) ([]string, []string) {
	baselineKeys := extractJSONKeys(baseline.Body)
	mutatedKeys := extractJSONKeys(mutated.Body)

	added := []string{}
	removed := []string{}

	baselineMap := make(map[string]bool)
	for _, k := range baselineKeys {
		baselineMap[k] = true
	}

	mutatedMap := make(map[string]bool)
	for _, k := range mutatedKeys {
		mutatedMap[k] = true
	}

	for _, k := range mutatedKeys {
		if !baselineMap[k] {
			added = append(added, k)
		}
	}

	for _, k := range baselineKeys {
		if !mutatedMap[k] {
			removed = append(removed, k)
		}
	}

	return added, removed
}

func extractJSONKeys(body []byte) []string {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return []string{}
	}

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	return keys
}

func (d *BodyDetector) GetEvidence(baseline, mutated *engine.ResponseContext) map[string]string {
	evidence := make(map[string]string)

	if baseline.BodyHash != mutated.BodyHash {
		evidence["body_changed"] = "true"
	}

	sensitive := d.DetectSensitiveData(mutated)
	if len(sensitive) > 0 {
		evidence["sensitive_data"] = strings.Join(sensitive, ", ")
	}

	added, removed := d.DetectJSONChanges(baseline, mutated)
	if len(added) > 0 {
		evidence["json_keys_added"] = strings.Join(added, ", ")
	}
	if len(removed) > 0 {
		evidence["json_keys_removed"] = strings.Join(removed, ", ")
	}

	return evidence
}
