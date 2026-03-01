package headers

import "github.com/cc1a2b/HHunter/engine"

func GetSmugglingMutations() []engine.Mutation {
	return []engine.Mutation{
		// Transfer-Encoding obfuscation (CL-TE / TE-CL detection)
		{Header: "Transfer-Encoding", Value: "chunked", Category: "Smuggling", Impact: "HTTP Request Smuggling"},
		{Header: "Transfer-Encoding", Value: " chunked", Category: "Smuggling", Impact: "TE Obfuscation - Leading Space"},
		{Header: "Transfer-Encoding", Value: "chunked ", Category: "Smuggling", Impact: "TE Obfuscation - Trailing Space"},
		{Header: "Transfer-Encoding", Value: "\tchunked", Category: "Smuggling", Impact: "TE Obfuscation - Tab Prefix"},
		{Header: "Transfer-Encoding", Value: "chunked\t", Category: "Smuggling", Impact: "TE Obfuscation - Tab Suffix"},
		{Header: "Transfer-Encoding", Value: "Chunked", Category: "Smuggling", Impact: "TE Obfuscation - Mixed Case"},
		{Header: "Transfer-Encoding", Value: "CHUNKED", Category: "Smuggling", Impact: "TE Obfuscation - Upper Case"},
		{Header: "Transfer-Encoding", Value: "cHuNkEd", Category: "Smuggling", Impact: "TE Obfuscation - Random Case"},
		{Header: "Transfer-Encoding", Value: "chunked, identity", Category: "Smuggling", Impact: "TE Dual Encoding"},
		{Header: "Transfer-Encoding", Value: "identity, chunked", Category: "Smuggling", Impact: "TE Dual Encoding Reverse"},
		{Header: "Transfer-Encoding", Value: "x]chunked", Category: "Smuggling", Impact: "TE Parser Confusion"},
		{Header: "Transfer-Encoding", Value: "chunked;ext=val", Category: "Smuggling", Impact: "TE Extension Parameter"},
		{Header: "Transfer-Encoding", Value: "x, chunked", Category: "Smuggling", Impact: "TE Invalid First Encoding"},
		{Header: "Transfer-Encoding", Value: "identity; chunked", Category: "Smuggling", Impact: "TE Semicolon Separator"},
		{Header: "Transfer-Encoding", Value: "compress", Category: "Smuggling", Impact: "TE Compress Encoding"},
		{Header: "Transfer-Encoding", Value: "deflate", Category: "Smuggling", Impact: "TE Deflate Encoding"},
		{Header: "Transfer-Encoding", Value: "gzip", Category: "Smuggling", Impact: "TE Gzip Encoding"},
		{Header: "Transfer-Encoding", Value: "cow", Category: "Smuggling", Impact: "TE Unknown Encoding"},

		// Content-Length manipulation
		{Header: "Content-Length", Value: "0", Category: "Smuggling", Impact: "CL Zero Body"},
		{Header: "Content-Length", Value: "-1", Category: "Smuggling", Impact: "CL Negative Length"},
		{Header: "Content-Length", Value: "99999999", Category: "Smuggling", Impact: "CL Oversized Length"},
		{Header: "Content-Length", Value: "0x10", Category: "Smuggling", Impact: "CL Hex Encoded"},
		{Header: "Content-Length", Value: "1e2", Category: "Smuggling", Impact: "CL Scientific Notation"},
		{Header: "Content-Length", Value: " 0", Category: "Smuggling", Impact: "CL Leading Space"},
		{Header: "Content-Length", Value: "+0", Category: "Smuggling", Impact: "CL Plus Prefix"},
		{Header: "Content-Length", Value: "00", Category: "Smuggling", Impact: "CL Leading Zero"},

		// Hop-by-hop smuggling via Connection header
		{Header: "Connection", Value: "keep-alive, Transfer-Encoding", Category: "Smuggling", Impact: "Hop-by-Hop TE Stripping"},
		{Header: "Connection", Value: "close, Transfer-Encoding", Category: "Smuggling", Impact: "Hop-by-Hop TE Close"},
		{Header: "Connection", Value: "Transfer-Encoding", Category: "Smuggling", Impact: "Connection TE Stripping"},

		// HTTP/2 downgrade indicators
		{Header: "Upgrade", Value: "h2c", Category: "Smuggling", Impact: "HTTP/2 Cleartext Upgrade"},
		{Header: "HTTP2-Settings", Value: "AAEAAEAAAAIAAAABAAMAAABkAAQBAAAAAAUAAEAA", Category: "Smuggling", Impact: "H2C Smuggling"},
		{Header: "Upgrade", Value: "HTTP/1.1", Category: "Smuggling", Impact: "HTTP Downgrade"},
		{Header: "Upgrade", Value: "HTTP/2.0", Category: "Smuggling", Impact: "HTTP/2 Upgrade"},

		// Request line manipulation via headers
		{Header: "X-HTTP-Version", Value: "HTTP/1.0", Category: "Smuggling", Impact: "HTTP Version Confusion"},
		{Header: "X-Forwarded-Proto", Value: "http/1.0", Category: "Smuggling", Impact: "Protocol Version Confusion"},

		// Trailer header (TE: trailers)
		{Header: "Trailer", Value: "Authorization", Category: "Smuggling", Impact: "Trailer Auth Injection"},
		{Header: "Trailer", Value: "Content-Type", Category: "Smuggling", Impact: "Trailer Content-Type Injection"},
		{Header: "TE", Value: "trailers", Category: "Smuggling", Impact: "Trailer Encoding Support"},
		{Header: "TE", Value: "chunked;q=0.5, trailers", Category: "Smuggling", Impact: "TE Quality Negotiation"},

		// Content-Type boundary confusion
		{Header: "Content-Type", Value: "multipart/form-data; boundary=----", Category: "Smuggling", Impact: "Multipart Boundary Confusion"},
		{Header: "Content-Type", Value: "application/x-www-form-urlencoded; charset=ibm037", Category: "Smuggling", Impact: "Charset Encoding Confusion"},
		{Header: "Content-Type", Value: "text/plain; charset=utf-7", Category: "Smuggling", Impact: "UTF-7 Charset Confusion"},
	}
}
