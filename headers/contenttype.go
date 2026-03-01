package headers

import "github.com/cc1a2b/hhunter/engine"

func GetContentTypeMutations() []engine.Mutation {
	mutations := []engine.Mutation{}

	// MIME type confusion — trick parser into processing content differently
	mimeConfusion := []struct {
		value  string
		impact string
	}{
		// Force HTML interpretation for XSS
		{"text/html", "Force HTML content type — potential XSS if body reflected"},
		{"text/html; charset=utf-7", "HTML with UTF-7 charset — encoding-based XSS"},
		{"text/html; charset=utf-8", "HTML with explicit UTF-8"},
		{"application/xhtml+xml", "XHTML content type — strict XML parsing may differ"},

		// Force XML for XXE
		{"application/xml", "Force XML content type — potential XXE"},
		{"text/xml", "Force text/xml — alternative XXE vector"},
		{"application/xml; charset=utf-8", "XML with charset — XXE attempt"},
		{"application/soap+xml", "SOAP XML content type"},

		// JSON confusion
		{"application/json", "Force JSON content type"},
		{"application/json; charset=utf-8", "JSON with explicit charset"},
		{"text/json", "Non-standard JSON content type"},
		{"application/vnd.api+json", "JSON:API content type"},
		{"application/ld+json", "JSON-LD content type"},
		{"application/csp-report", "CSP report content type"},

		// JavaScript injection
		{"application/javascript", "Force JavaScript content type"},
		{"text/javascript", "Force text/javascript"},
		{"application/ecmascript", "ECMAScript content type"},

		// SVG for XSS
		{"image/svg+xml", "SVG content type — potential XSS via SVG"},

		// Multipart manipulation
		{"multipart/form-data; boundary=----WebKitFormBoundary", "Multipart with WebKit boundary"},
		{"multipart/form-data; boundary=evil", "Multipart with custom boundary"},
		{"multipart/mixed; boundary=----", "Multipart mixed type"},
		{"multipart/form-data; boundary=------WebKitFormBoundaryabc\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"", "Multipart boundary injection"},

		// MIME sniffing triggers
		{"application/octet-stream", "Binary content type — forces MIME sniffing"},
		{"application/unknown", "Unknown MIME — triggers content sniffing"},
		{"text/plain", "Plain text — some browsers still sniff"},
		{"", "Empty content type — server decides"},

		// WAF bypass via content type confusion
		{"application/x-www-form-urlencoded", "Form URL encoded — WAF may process differently"},
		{"application/x-www-form-urlencoded; charset=ibm037", "URL encoded with EBCDIC charset — WAF bypass"},
		{"application/x-www-form-urlencoded; charset=utf-7", "URL encoded with UTF-7 — WAF bypass"},
		{"application/x-www-form-urlencoded; charset=us-ascii", "URL encoded with ASCII charset"},

		// Charset-based WAF bypass
		{"application/json; charset=ibm037", "JSON with EBCDIC charset — WAF evasion"},
		{"application/json; charset=ibm500", "JSON with IBM500 charset — WAF evasion"},
		{"application/json; charset=cp875", "JSON with CP875 charset — WAF evasion"},
		{"application/json; charset=utf-16", "JSON with UTF-16 — WAF evasion"},
		{"application/json; charset=utf-16be", "JSON with UTF-16 big endian"},
		{"application/json; charset=utf-32", "JSON with UTF-32 — WAF evasion"},
		{"application/json; charset=shift_jis", "JSON with Shift-JIS charset"},
		{"application/json; charset=iso-2022-jp", "JSON with ISO-2022-JP charset"},

		// SSRF via content type
		{"application/x-dtbncx+xml", "DTB NCX XML — potential XXE"},
		{"application/rss+xml", "RSS XML — potential XXE/SSRF"},
		{"application/atom+xml", "Atom XML — potential XXE/SSRF"},

		// File upload bypass
		{"image/jpeg", "Image content type — file upload bypass"},
		{"image/png", "PNG content type — file upload bypass"},
		{"image/gif", "GIF content type — file upload bypass"},
		{"application/pdf", "PDF content type"},
		{"application/zip", "ZIP content type"},

		// Protocol buffers / gRPC
		{"application/grpc", "gRPC content type"},
		{"application/grpc+proto", "gRPC with protobuf"},
		{"application/x-protobuf", "Protocol buffers content type"},

		// GraphQL
		{"application/graphql", "GraphQL content type"},

		// YAML (some APIs accept YAML)
		{"application/x-yaml", "YAML content type — deserialization risk"},
		{"text/yaml", "YAML text content type"},
		{"text/x-yaml", "YAML alternative content type"},
	}

	for _, mc := range mimeConfusion {
		mutations = append(mutations, engine.Mutation{
			Header:   "Content-Type",
			Value:    mc.value,
			Category: "ContentType",
			Impact:   "Content-Type manipulation: " + mc.impact,
		})
	}

	// Accept header manipulation — influence response content type
	acceptMutations := []struct {
		value  string
		impact string
	}{
		{"text/html, application/xhtml+xml", "Request HTML response — may expose web interface"},
		{"application/xml, text/xml", "Request XML response — different parser, potential XXE"},
		{"application/json", "Request JSON — may expose API data"},
		{"text/csv", "Request CSV — data export"},
		{"application/pdf", "Request PDF export"},
		{"*/*", "Accept anything — widest content negotiation"},
		{"application/vnd.api+json", "JSON:API negotiation"},
		{"text/event-stream", "Request SSE stream"},
		{"text/plain", "Request plain text — may bypass encoding"},
		{"application/octet-stream", "Request binary — download file"},
		{"image/svg+xml", "Request SVG — potential XSS context"},
	}

	for _, am := range acceptMutations {
		mutations = append(mutations, engine.Mutation{
			Header:   "Accept",
			Value:    am.value,
			Category: "ContentType",
			Impact:   "Accept header manipulation: " + am.impact,
		})
	}

	// Content-Encoding manipulation
	encodingMutations := []struct {
		header string
		value  string
		impact string
	}{
		{"Content-Encoding", "gzip", "Content-Encoding gzip — may bypass WAF inspection"},
		{"Content-Encoding", "deflate", "Content-Encoding deflate — WAF bypass"},
		{"Content-Encoding", "br", "Content-Encoding brotli — WAF bypass"},
		{"Content-Encoding", "identity", "Content-Encoding identity — no compression"},
		{"Content-Encoding", "chunked", "Content-Encoding chunked — parser confusion"},
		{"Content-Encoding", "gzip, deflate", "Stacked content encoding"},
		{"Content-Encoding", "gzip\r\nContent-Encoding: deflate", "Double Content-Encoding (CRLF)"},
	}

	for _, em := range encodingMutations {
		mutations = append(mutations, engine.Mutation{
			Header:   em.header,
			Value:    em.value,
			Category: "ContentType",
			Impact:   em.impact,
		})
	}

	return mutations
}
