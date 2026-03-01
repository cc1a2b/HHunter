package engine

import (
	"regexp"
	"strings"
)

// ResponseSimilarity provides semantic comparison between HTTP responses,
// going beyond simple hash comparison to handle dynamic content intelligently.

// SimilarityResult holds the detailed comparison between two responses
type SimilarityResult struct {
	// BodySimilarity is 0.0 (completely different) to 1.0 (identical)
	BodySimilarity float64

	// StructuralSimilarity compares HTML/JSON structure ignoring content
	StructuralSimilarity float64

	// HeaderSimilarity compares response header sets
	HeaderSimilarity float64

	// NormalizedBodySimilarity is body similarity after removing dynamic content
	NormalizedBodySimilarity float64

	// OverallScore is the weighted composite score
	OverallScore float64

	// IsDynamic indicates the baseline response has dynamic content
	IsDynamic bool

	// DynamicPatterns lists detected dynamic content patterns
	DynamicPatterns []string
}

// Dynamic content patterns to normalize before comparison
var dynamicPatterns = []*regexp.Regexp{
	// Timestamps
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.\d]*Z?`),
	regexp.MustCompile(`\d{10,13}`), // Unix timestamps

	// UUIDs
	regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),

	// Session tokens / random hex strings (32+ chars)
	regexp.MustCompile(`[0-9a-f]{32,}`),

	// CSRF tokens in HTML
	regexp.MustCompile(`name="csrf[_-]?token"\s+value="[^"]+"`),
	regexp.MustCompile(`name="_token"\s+value="[^"]+"`),

	// Nonces
	regexp.MustCompile(`nonce="[^"]+"`),
	regexp.MustCompile(`nonce-[A-Za-z0-9+/=]+`),

	// Request IDs
	regexp.MustCompile(`"request[_-]?id"\s*:\s*"[^"]+"`),
	regexp.MustCompile(`"trace[_-]?id"\s*:\s*"[^"]+"`),
	regexp.MustCompile(`"correlation[_-]?id"\s*:\s*"[^"]+"`),
}

// CalculateSimilarity computes a detailed similarity analysis between two responses
func CalculateSimilarity(baseline, mutated *ResponseContext) *SimilarityResult {
	result := &SimilarityResult{}

	baseBody := string(baseline.Body)
	mutBody := string(mutated.Body)

	// Raw body similarity
	result.BodySimilarity = stringSimilarity(baseBody, mutBody)

	// Detect dynamic patterns in baseline
	result.DynamicPatterns = detectDynamicPatterns(baseBody)
	result.IsDynamic = len(result.DynamicPatterns) > 0

	// Normalized body similarity (strip dynamic content)
	normalizedBase := normalizeDynamicContent(baseBody)
	normalizedMut := normalizeDynamicContent(mutBody)
	result.NormalizedBodySimilarity = stringSimilarity(normalizedBase, normalizedMut)

	// Structural similarity (HTML tags / JSON keys only)
	result.StructuralSimilarity = structuralSimilarity(baseBody, mutBody)

	// Header similarity
	result.HeaderSimilarity = headerSimilarity(baseline.Headers, mutated.Headers)

	// Composite score: weight normalized body highest, then structure, then headers
	result.OverallScore = result.NormalizedBodySimilarity*0.5 +
		result.StructuralSimilarity*0.3 +
		result.HeaderSimilarity*0.2

	return result
}

// CalculateSimilarityWithProfile uses baseline profile for better dynamic detection
func CalculateSimilarityWithProfile(baseline, mutated *ResponseContext, profile *BaselineProfile) *SimilarityResult {
	result := CalculateSimilarity(baseline, mutated)

	// If profile shows body is inconsistent, lower our confidence in body similarity
	if profile != nil && !profile.BodyConsistent {
		result.IsDynamic = true
		// Re-weight: rely more on structural similarity
		result.OverallScore = result.NormalizedBodySimilarity*0.3 +
			result.StructuralSimilarity*0.5 +
			result.HeaderSimilarity*0.2
	}

	return result
}

// stringSimilarity computes a ratio of common characters between two strings
// using a simplified sequence matcher approach (0.0 to 1.0)
func stringSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	// For very large responses, use line-level comparison for performance
	if len(a) > 10000 || len(b) > 10000 {
		return lineSimilarity(a, b)
	}

	// Compute longest common subsequence ratio
	return lcsRatio(a, b)
}

// lineSimilarity compares strings line by line for large responses
func lineSimilarity(a, b string) float64 {
	linesA := strings.Split(a, "\n")
	linesB := strings.Split(b, "\n")

	if len(linesA) == 0 && len(linesB) == 0 {
		return 1.0
	}

	// Build set of lines from B
	setBLines := make(map[string]int)
	for _, line := range linesB {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			setBLines[trimmed]++
		}
	}

	// Count matching lines
	matched := 0
	totalA := 0
	for _, line := range linesA {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		totalA++
		if count, exists := setBLines[trimmed]; exists && count > 0 {
			matched++
			setBLines[trimmed]--
		}
	}

	totalB := 0
	for _, line := range linesB {
		if strings.TrimSpace(line) != "" {
			totalB++
		}
	}

	if totalA == 0 && totalB == 0 {
		return 1.0
	}

	maxTotal := totalA
	if totalB > maxTotal {
		maxTotal = totalB
	}

	return float64(matched*2) / float64(totalA+totalB)
}

// lcsRatio computes LCS-based similarity ratio
func lcsRatio(a, b string) float64 {
	// Downsample for performance if strings are long
	if len(a) > 2000 {
		a = a[:2000]
	}
	if len(b) > 2000 {
		b = b[:2000]
	}

	lcsLen := lcsLength(a, b)
	return float64(2*lcsLen) / float64(len(a)+len(b))
}

// lcsLength computes length of longest common subsequence
func lcsLength(a, b string) int {
	m := len(a)
	n := len(b)

	// Space-optimized LCS using two rows
	prev := make([]int, n+1)
	curr := make([]int, n+1)

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if a[i-1] == b[j-1] {
				curr[j] = prev[j-1] + 1
			} else {
				curr[j] = prev[j]
				if curr[j-1] > curr[j] {
					curr[j] = curr[j-1]
				}
			}
		}
		prev, curr = curr, prev
		for k := range curr {
			curr[k] = 0
		}
	}

	return prev[n]
}

// normalizeDynamicContent strips dynamic content from a response body
func normalizeDynamicContent(body string) string {
	normalized := body
	for _, pattern := range dynamicPatterns {
		normalized = pattern.ReplaceAllString(normalized, "{{DYNAMIC}}")
	}
	return normalized
}

// detectDynamicPatterns identifies which dynamic patterns exist in the body
func detectDynamicPatterns(body string) []string {
	var found []string
	patternNames := []string{
		"timestamp_iso", "timestamp_unix",
		"uuid",
		"hex_token",
		"csrf_token", "csrf_token_alt",
		"nonce_attr", "nonce_csp",
		"request_id", "trace_id", "correlation_id",
	}

	for i, pattern := range dynamicPatterns {
		if pattern.MatchString(body) {
			name := "unknown"
			if i < len(patternNames) {
				name = patternNames[i]
			}
			found = append(found, name)
		}
	}
	return found
}

// structuralSimilarity compares the structural elements of two response bodies
func structuralSimilarity(a, b string) float64 {
	structA := extractStructure(a)
	structB := extractStructure(b)

	if structA == "" && structB == "" {
		return 1.0
	}

	return stringSimilarity(structA, structB)
}

// extractStructure extracts structural skeleton from HTML or JSON
func extractStructure(body string) string {
	body = strings.TrimSpace(body)
	if len(body) == 0 {
		return ""
	}

	// JSON structure: extract key paths
	if (body[0] == '{' || body[0] == '[') {
		keys := extractJSONKeys([]byte(body))
		return strings.Join(keys, "\n")
	}

	// HTML structure: extract tag sequence
	return extractHTMLStructure(body)
}

// extractHTMLStructure extracts the tag structure from HTML
func extractHTMLStructure(html string) string {
	tagPattern := regexp.MustCompile(`</?[a-zA-Z][a-zA-Z0-9]*[^>]*>`)
	tags := tagPattern.FindAllString(html, -1)

	// Simplify tags — keep only tag name and key attributes
	var simplified []string
	tagNamePattern := regexp.MustCompile(`^</?([a-zA-Z][a-zA-Z0-9]*)`)

	for _, tag := range tags {
		matches := tagNamePattern.FindStringSubmatch(tag)
		if len(matches) > 1 {
			simplified = append(simplified, matches[0])
		}
	}

	return strings.Join(simplified, "\n")
}

// headerSimilarity compares two sets of response headers
func headerSimilarity(a, b map[string][]string) float64 {
	setA := make(map[string]bool)
	setB := make(map[string]bool)

	for k := range a {
		setA[strings.ToLower(k)] = true
	}
	for k := range b {
		setB[strings.ToLower(k)] = true
	}

	if len(setA) == 0 && len(setB) == 0 {
		return 1.0
	}

	// Jaccard similarity
	intersection := 0
	for k := range setA {
		if setB[k] {
			intersection++
		}
	}

	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 1.0
	}

	return float64(intersection) / float64(union)
}

// IsResponseSignificantlyDifferent returns true if the mutation response
// is meaningfully different from the baseline, accounting for dynamic content
func IsResponseSignificantlyDifferent(baseline, mutated *ResponseContext, profile *BaselineProfile) bool {
	sim := CalculateSimilarityWithProfile(baseline, mutated, profile)

	// If overall similarity is high, the response is essentially the same
	if sim.OverallScore > 0.95 {
		return false
	}

	// If structural similarity is high but body different, likely just dynamic content
	if sim.StructuralSimilarity > 0.95 && sim.NormalizedBodySimilarity > 0.9 {
		return false
	}

	// Meaningful difference detected
	return true
}
