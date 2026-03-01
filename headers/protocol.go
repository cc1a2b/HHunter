package headers

import "github.com/cc1a2b/HHunter/engine"

func GetProtocolMutations() []engine.Mutation {
	mutations := []engine.Mutation{}

	// h2c smuggling — upgrade HTTP/1.1 to HTTP/2 cleartext
	h2cMutations := []struct {
		header string
		value  string
		impact string
	}{
		// h2c upgrade via Connection + Upgrade
		{"Upgrade", "h2c", "HTTP/2 cleartext upgrade — h2c smuggling"},
		{"Upgrade", "h2c, websocket", "h2c upgrade with WebSocket fallback"},
		{"HTTP2-Settings", "AAMAAABkAAQCAAAAAAIAAAAA", "HTTP/2 settings for h2c upgrade"},
		{"Connection", "Upgrade, HTTP2-Settings", "Connection header for h2c upgrade"},

		// Websocket upgrade for hijacking
		{"Upgrade", "websocket", "WebSocket upgrade attempt"},
		{"Connection", "Upgrade", "Connection upgrade header"},
		{"Sec-WebSocket-Version", "13", "WebSocket version 13"},
		{"Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==", "WebSocket key for upgrade"},

		// HTTPS downgrade
		{"Upgrade-Insecure-Requests", "0", "Disable upgrade to HTTPS"},
		{"Upgrade-Insecure-Requests", "1", "Force upgrade to HTTPS"},

		// TLS/SSL manipulation
		{"X-Forwarded-Ssl", "off", "Disable SSL detection"},
		{"X-Forwarded-Ssl", "on", "Force SSL detection"},
		{"Front-End-Https", "off", "Disable front-end HTTPS"},
		{"Front-End-Https", "on", "Force front-end HTTPS"},
		{"X-Url-Scheme", "http", "URL scheme downgrade"},
		{"X-Url-Scheme", "https", "URL scheme upgrade"},
	}

	for _, m := range h2cMutations {
		mutations = append(mutations, engine.Mutation{
			Header:   m.header,
			Value:    m.value,
			Category: "Protocol",
			Impact:   m.impact,
		})
	}

	// HTTP/2 pseudo-header injection (via header name manipulation)
	pseudoHeaders := []struct {
		header string
		value  string
		impact string
	}{
		{":method", "TRACE", "HTTP/2 pseudo-header method override to TRACE"},
		{":method", "CONNECT", "HTTP/2 pseudo-header method override to CONNECT"},
		{":path", "/admin", "HTTP/2 pseudo-header path override"},
		{":path", "/../../../etc/passwd", "HTTP/2 pseudo-header path traversal"},
		{":authority", "evil.com", "HTTP/2 pseudo-header authority override"},
		{":scheme", "http", "HTTP/2 pseudo-header scheme downgrade"},
		{":scheme", "https", "HTTP/2 pseudo-header scheme override"},
		{":status", "200", "HTTP/2 pseudo-header status injection"},
	}

	for _, ph := range pseudoHeaders {
		mutations = append(mutations, engine.Mutation{
			Header:   ph.header,
			Value:    ph.value,
			Category: "Protocol",
			Impact:   "HTTP/2 pseudo-header injection: " + ph.impact,
		})
	}

	// HTTP version manipulation
	versionHeaders := []struct {
		header string
		value  string
		impact string
	}{
		{"X-HTTP-Version", "1.0", "Force HTTP/1.0 — disable keep-alive, chunked encoding"},
		{"X-HTTP-Version", "1.1", "Force HTTP/1.1"},
		{"X-HTTP-Version", "2.0", "Force HTTP/2"},
		{"X-HTTP-Version", "3.0", "Force HTTP/3"},
		{"X-Forwarded-HTTP-Version", "1.0", "Forwarded HTTP version downgrade"},
	}

	for _, vh := range versionHeaders {
		mutations = append(mutations, engine.Mutation{
			Header:   vh.header,
			Value:    vh.value,
			Category: "Protocol",
			Impact:   "HTTP version manipulation: " + vh.impact,
		})
	}

	// Alt-Svc header manipulation — redirect to attacker-controlled protocol endpoint
	altSvcMutations := []struct {
		value  string
		impact string
	}{
		{`h2="evil.com:443"; ma=86400`, "Alt-Svc redirect to attacker H2 endpoint"},
		{`h3=":443"; ma=86400`, "Alt-Svc HTTP/3 alternative"},
		{`h2c="evil.com:80"; ma=86400`, "Alt-Svc h2c redirect — cleartext"},
		{"clear", "Alt-Svc clear — remove cached alternatives"},
	}

	for _, as := range altSvcMutations {
		mutations = append(mutations, engine.Mutation{
			Header:   "Alt-Svc",
			Value:    as.value,
			Category: "Protocol",
			Impact:   "Alt-Svc manipulation: " + as.impact,
		})
	}

	// Expect header abuse
	expectMutations := []struct {
		value  string
		impact string
	}{
		{"100-continue", "Expect 100 Continue — probe server behavior"},
		{"102-processing", "Expect 102 Processing — WebDAV probe"},
		{"", "Empty Expect header — error handling probe"},
	}

	for _, em := range expectMutations {
		mutations = append(mutations, engine.Mutation{
			Header:   "Expect",
			Value:    em.value,
			Category: "Protocol",
			Impact:   "Expect header abuse: " + em.impact,
		})
	}

	// Keep-Alive / Connection manipulation
	connectionMutations := []struct {
		header string
		value  string
		impact string
	}{
		{"Connection", "close", "Force connection close"},
		{"Connection", "keep-alive", "Force keep-alive"},
		{"Connection", "Upgrade, keep-alive", "Upgrade + keep-alive"},
		{"Keep-Alive", "timeout=0", "Zero timeout — force connection drop"},
		{"Keep-Alive", "timeout=999999, max=999999", "Extremely long keep-alive"},
		{"Proxy-Connection", "keep-alive", "Proxy connection keep-alive"},
		{"Proxy-Connection", "close", "Proxy connection close"},
	}

	for _, cm := range connectionMutations {
		mutations = append(mutations, engine.Mutation{
			Header:   cm.header,
			Value:    cm.value,
			Category: "Protocol",
			Impact:   "Connection manipulation: " + cm.impact,
		})
	}

	// Trailer header injection
	trailerMutations := []struct {
		value  string
		impact string
	}{
		{"Authorization", "Trailer header — inject Authorization after body"},
		{"Content-Type", "Trailer header — change Content-Type after body"},
		{"X-Forwarded-For", "Trailer header — inject XFF after body"},
		{"Transfer-Encoding", "Trailer header — TE in trailers (smuggling)"},
	}

	for _, tm := range trailerMutations {
		mutations = append(mutations, engine.Mutation{
			Header:   "Trailer",
			Value:    tm.value,
			Category: "Protocol",
			Impact:   "Trailer header injection: " + tm.impact,
		})
	}

	// TE header for protocol confusion
	teMutations := []struct {
		value  string
		impact string
	}{
		{"trailers", "TE trailers — enable trailer headers"},
		{"gzip", "TE gzip — encoding negotiation probe"},
		{"deflate", "TE deflate — encoding negotiation probe"},
		{"trailers, gzip", "TE combined — trailers with compression"},
	}

	for _, te := range teMutations {
		mutations = append(mutations, engine.Mutation{
			Header:   "TE",
			Value:    te.value,
			Category: "Protocol",
			Impact:   "TE header manipulation: " + te.impact,
		})
	}

	return mutations
}
