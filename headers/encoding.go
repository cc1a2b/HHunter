package headers

import "github.com/cc1a2b/HHunter/engine"

func GetEncodingMutations() []engine.Mutation {
	mutations := []engine.Mutation{}

	// Accept-Encoding manipulation — compression oracle / WAF bypass
	acceptEncoding := []struct {
		value  string
		impact string
	}{
		{"gzip", "Standard gzip — compression oracle (BREACH/CRIME) indicator"},
		{"deflate", "Deflate encoding — compression oracle indicator"},
		{"br", "Brotli encoding — newer compression"},
		{"zstd", "Zstandard encoding — modern compression"},
		{"identity", "Identity encoding — no compression"},
		{"*", "Accept any encoding"},
		{"gzip, deflate, br", "All common encodings"},
		{"compress", "LZW compress — legacy encoding"},
		{"x-gzip", "Non-standard gzip alias"},
		{"gzip;q=0", "Reject gzip — force uncompressed"},
		{"identity;q=0", "Reject identity — may cause error"},
		{"*;q=0", "Reject all encodings — may cause 406"},
		{"chunked", "Chunked in Accept-Encoding — invalid but may confuse"},
		{"gzip\x00deflate", "Null byte in encoding — parser confusion"},
	}

	for _, ae := range acceptEncoding {
		mutations = append(mutations, engine.Mutation{
			Header:   "Accept-Encoding",
			Value:    ae.value,
			Category: "Encoding",
			Impact:   "Accept-Encoding manipulation: " + ae.impact,
		})
	}

	// Accept-Language manipulation — locale-based access control bypass
	acceptLanguage := []struct {
		value  string
		impact string
	}{
		{"en-US,en;q=0.9", "Standard US English"},
		{"*", "Accept any language — widest negotiation"},
		{"zh-CN", "Chinese locale — may expose different content"},
		{"ja", "Japanese locale"},
		{"ko", "Korean locale"},
		{"ar", "Arabic locale — RTL content"},
		{"de", "German locale"},
		{"fr", "French locale"},
		{"ru", "Russian locale"},
		{"en-GB;q=0.9, *;q=0.1", "British English with fallback"},
		{"xx-XX", "Invalid locale — error handling probe"},
		{"en-US\r\nX-Injected: true", "CRLF in Accept-Language"},
		{"C", "POSIX C locale — internal/debug behavior"},
		{"en, admin", "Locale injection — admin keyword"},
	}

	for _, al := range acceptLanguage {
		mutations = append(mutations, engine.Mutation{
			Header:   "Accept-Language",
			Value:    al.value,
			Category: "Encoding",
			Impact:   "Accept-Language manipulation: " + al.impact,
		})
	}

	// Accept-Charset manipulation — charset-based WAF bypass
	acceptCharset := []struct {
		value  string
		impact string
	}{
		{"utf-8", "Standard UTF-8"},
		{"utf-7", "UTF-7 — XSS bypass via charset confusion"},
		{"utf-16", "UTF-16 — WAF bypass"},
		{"utf-32", "UTF-32 — WAF bypass"},
		{"iso-8859-1", "Latin-1 charset"},
		{"windows-1252", "Windows-1252 charset"},
		{"ibm037", "EBCDIC charset — WAF bypass"},
		{"ibm500", "EBCDIC international — WAF bypass"},
		{"cp875", "EBCDIC Greek — WAF bypass"},
		{"shift_jis", "Shift-JIS — CJK charset"},
		{"euc-jp", "EUC-JP — Japanese charset"},
		{"iso-2022-jp", "ISO-2022-JP — stateful charset"},
		{"gb2312", "Chinese simplified charset"},
		{"big5", "Chinese traditional charset"},
		{"*", "Accept any charset"},
		{"us-ascii", "ASCII only"},
	}

	for _, ac := range acceptCharset {
		mutations = append(mutations, engine.Mutation{
			Header:   "Accept-Charset",
			Value:    ac.value,
			Category: "Encoding",
			Impact:   "Accept-Charset manipulation: " + ac.impact,
		})
	}

	// Content-Language manipulation
	contentLanguage := []struct {
		value  string
		impact string
	}{
		{"en", "Content-Language English"},
		{"*", "Content-Language wildcard"},
		{"en, admin", "Content-Language injection"},
	}

	for _, cl := range contentLanguage {
		mutations = append(mutations, engine.Mutation{
			Header:   "Content-Language",
			Value:    cl.value,
			Category: "Encoding",
			Impact:   "Content-Language manipulation: " + cl.impact,
		})
	}

	// Charset injection via X-headers
	charsetHeaders := []struct {
		header string
		value  string
		impact string
	}{
		{"X-Content-Charset", "utf-7", "Charset override — UTF-7 XSS vector"},
		{"X-Content-Charset", "ibm037", "Charset override — EBCDIC WAF bypass"},
		{"X-Response-Charset", "utf-7", "Response charset override"},
		{"X-Charset", "utf-16", "Charset override — UTF-16 WAF bypass"},
		{"X-Encoding", "base64", "Encoding override — base64"},
		{"X-Encoding", "gzip", "Encoding override — gzip"},
		{"X-Content-Encoding", "gzip", "Content encoding override"},
		{"X-Transfer-Encoding", "chunked", "Transfer encoding override"},
	}

	for _, ch := range charsetHeaders {
		mutations = append(mutations, engine.Mutation{
			Header:   ch.header,
			Value:    ch.value,
			Category: "Encoding",
			Impact:   ch.impact,
		})
	}

	// Range header attacks — information disclosure, DoS
	rangeMutations := []struct {
		value  string
		impact string
	}{
		{"bytes=0-0", "First byte only — fingerprint content"},
		{"bytes=0-", "All bytes from start"},
		{"bytes=-1", "Last byte only"},
		{"bytes=0-0,1-1,2-2,3-3,4-4,5-5,6-6,7-7,8-8,9-9", "Overlapping ranges — DoS (Apache Killer style)"},
		{"bytes=0-0,0-1,0-2,0-3,0-4,0-5,0-6,0-7,0-8,0-9,0-10,0-11,0-12,0-13,0-14,0-15,0-16,0-17,0-18,0-19", "Many overlapping ranges — resource exhaustion"},
		{"bytes=0-999999999", "Huge range request"},
		{"bytes=999999999-0", "Reversed range — parser confusion"},
		{"bytes=0-0,-1", "First and last byte — content sniff"},
		{"none", "Invalid range unit"},
	}

	for _, rm := range rangeMutations {
		mutations = append(mutations, engine.Mutation{
			Header:   "Range",
			Value:    rm.value,
			Category: "Encoding",
			Impact:   "Range header attack: " + rm.impact,
		})
	}

	// If-Range / If-Match / If-None-Match manipulation
	conditionalMutations := []struct {
		header string
		value  string
		impact string
	}{
		{"If-Range", "invalid-etag", "If-Range with invalid ETag"},
		{"If-Range", "*", "If-Range wildcard"},
		{"If-Range", "Wed, 01 Jan 2020 00:00:00 GMT", "If-Range with old date — force full response"},
		{"If-Match", "*", "If-Match wildcard — bypass conditional checks"},
		{"If-Match", "\"invalid\"", "If-Match with fake ETag"},
		{"If-None-Match", "*", "If-None-Match wildcard — cache bypass"},
		{"If-None-Match", "\"0\"", "If-None-Match zeroed ETag"},
		{"If-Modified-Since", "Thu, 01 Jan 1970 00:00:00 GMT", "If-Modified-Since epoch — always modified"},
		{"If-Modified-Since", "Sat, 01 Jan 2050 00:00:00 GMT", "If-Modified-Since future — 304 probe"},
		{"If-Unmodified-Since", "Thu, 01 Jan 1970 00:00:00 GMT", "If-Unmodified-Since epoch — should fail with 412"},
	}

	for _, cm := range conditionalMutations {
		mutations = append(mutations, engine.Mutation{
			Header:   cm.header,
			Value:    cm.value,
			Category: "Encoding",
			Impact:   "Conditional header manipulation: " + cm.impact,
		})
	}

	return mutations
}
