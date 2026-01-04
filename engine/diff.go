package engine

import (
	"encoding/json"
	"math"
	"strings"
)

type DiffResult struct {
	StatusChanged    bool
	BodyHashChanged  bool
	NewJSONKeys      []string
	SizeChangeRatio  float64
	TimingDeltaMS    int64
	HeadersAdded     []string
	HeadersRemoved   []string
	PrivilegeElevate bool
	AuthBypass       bool
}

func CalculateDiff(baseline, mutated *ResponseContext) *DiffResult {
	diff := &DiffResult{}

	diff.StatusChanged = baseline.StatusCode != mutated.StatusCode
	diff.BodyHashChanged = baseline.BodyHash != mutated.BodyHash
	diff.TimingDeltaMS = mutated.TimingMS - baseline.TimingMS

	if baseline.ContentLength > 0 {
		diff.SizeChangeRatio = float64(mutated.ContentLength) / float64(baseline.ContentLength)
	}

	baselineKeys := extractJSONKeys(baseline.Body)
	mutatedKeys := extractJSONKeys(mutated.Body)
	diff.NewJSONKeys = findNewKeys(baselineKeys, mutatedKeys)

	diff.HeadersAdded = findNewHeaders(baseline.Headers, mutated.Headers)
	diff.HeadersRemoved = findRemovedHeaders(baseline.Headers, mutated.Headers)

	diff.AuthBypass = detectAuthBypass(baseline, mutated)
	diff.PrivilegeElevate = detectPrivilegeElevation(baseline, mutated)

	return diff
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

func findNewKeys(baseline, mutated []string) []string {
	baselineMap := make(map[string]bool)
	for _, k := range baseline {
		baselineMap[k] = true
	}

	newKeys := []string{}
	for _, k := range mutated {
		if !baselineMap[k] {
			newKeys = append(newKeys, k)
		}
	}
	return newKeys
}

func findNewHeaders(baseline, mutated map[string][]string) []string {
	newHeaders := []string{}
	for k := range mutated {
		if _, exists := baseline[k]; !exists {
			newHeaders = append(newHeaders, k)
		}
	}
	return newHeaders
}

func findRemovedHeaders(baseline, mutated map[string][]string) []string {
	removed := []string{}
	for k := range baseline {
		if _, exists := mutated[k]; !exists {
			removed = append(removed, k)
		}
	}
	return removed
}

func detectAuthBypass(baseline, mutated *ResponseContext) bool {
	if baseline.StatusCode == 401 && mutated.StatusCode == 200 {
		return true
	}
	if baseline.StatusCode == 403 && mutated.StatusCode == 200 {
		return true
	}

	baselineBody := strings.ToLower(string(baseline.Body))
	mutatedBody := strings.ToLower(string(mutated.Body))

	if strings.Contains(baselineBody, "unauthorized") && !strings.Contains(mutatedBody, "unauthorized") {
		return true
	}
	if strings.Contains(baselineBody, "forbidden") && !strings.Contains(mutatedBody, "forbidden") {
		return true
	}

	return false
}

func detectPrivilegeElevation(baseline, mutated *ResponseContext) bool {
	baselineKeys := extractJSONKeys(baseline.Body)
	mutatedKeys := extractJSONKeys(mutated.Body)

	baselinePriv := countPrivilegeKeys(baselineKeys)
	mutatedPriv := countPrivilegeKeys(mutatedKeys)

	if mutatedPriv > baselinePriv {
		return true
	}

	baselineBody := strings.ToLower(string(baseline.Body))
	mutatedBody := strings.ToLower(string(mutated.Body))

	if !strings.Contains(baselineBody, "admin") && strings.Contains(mutatedBody, "admin") {
		return true
	}

	return false
}

func countPrivilegeKeys(keys []string) int {
	count := 0
	privilegeTerms := []string{"admin", "role", "permission", "privilege", "super"}

	for _, key := range keys {
		lowerKey := strings.ToLower(key)
		for _, term := range privilegeTerms {
			if strings.Contains(lowerKey, term) {
				count++
				break
			}
		}
	}
	return count
}

func (d *DiffResult) IsSignificant() bool {
	if d.StatusChanged {
		return true
	}
	if d.AuthBypass {
		return true
	}
	if d.PrivilegeElevate {
		return true
	}
	if len(d.NewJSONKeys) > 0 {
		return true
	}
	if math.Abs(d.SizeChangeRatio-1.0) > 0.2 {
		return true
	}
	if len(d.HeadersAdded) > 0 {
		return true
	}
	return false
}
