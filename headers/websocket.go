package headers

import "github.com/cc1a2b/HHunter/engine"

func GetWebSocketMutations() []engine.Mutation {
	return []engine.Mutation{
		// WebSocket upgrade attacks
		{Header: "Upgrade", Value: "websocket", Category: "WebSocket", Impact: "WebSocket Upgrade"},
		{Header: "Connection", Value: "Upgrade", Category: "WebSocket", Impact: "WebSocket Connection Upgrade"},
		{Header: "Sec-WebSocket-Version", Value: "13", Category: "WebSocket", Impact: "WebSocket Version Probe"},
		{Header: "Sec-WebSocket-Version", Value: "8", Category: "WebSocket", Impact: "WebSocket Legacy Version"},
		{Header: "Sec-WebSocket-Key", Value: "dGhlIHNhbXBsZSBub25jZQ==", Category: "WebSocket", Impact: "WebSocket Key Injection"},
		{Header: "Sec-WebSocket-Protocol", Value: "chat, superchat", Category: "WebSocket", Impact: "WebSocket Protocol Negotiation"},
		{Header: "Sec-WebSocket-Extensions", Value: "permessage-deflate", Category: "WebSocket", Impact: "WebSocket Extension Probe"},

		// Cross-site WebSocket hijacking
		{Header: "Origin", Value: "https://evil.com", Category: "WebSocket", Impact: "Cross-Site WebSocket Hijacking"},
		{Header: "Origin", Value: "null", Category: "WebSocket", Impact: "WebSocket Null Origin Hijacking"},

		// Server-Sent Events
		{Header: "Accept", Value: "text/event-stream", Category: "WebSocket", Impact: "SSE Stream Access"},
		{Header: "Cache-Control", Value: "no-cache", Category: "WebSocket", Impact: "SSE Cache Bypass"},
		{Header: "Last-Event-ID", Value: "0", Category: "WebSocket", Impact: "SSE Event Replay"},
		{Header: "Last-Event-ID", Value: "99999999", Category: "WebSocket", Impact: "SSE Event ID Manipulation"},

		// gRPC probe
		{Header: "Content-Type", Value: "application/grpc", Category: "WebSocket", Impact: "gRPC Protocol Probe"},
		{Header: "Content-Type", Value: "application/grpc-web", Category: "WebSocket", Impact: "gRPC-Web Protocol Probe"},
		{Header: "Content-Type", Value: "application/grpc+proto", Category: "WebSocket", Impact: "gRPC Proto Probe"},
		{Header: "TE", Value: "trailers", Category: "WebSocket", Impact: "gRPC Trailers Support"},
		{Header: "Grpc-Timeout", Value: "1S", Category: "WebSocket", Impact: "gRPC Timeout Probe"},

		// GraphQL endpoint probe
		{Header: "Content-Type", Value: "application/graphql", Category: "WebSocket", Impact: "GraphQL Content-Type Probe"},
		{Header: "X-GraphQL-Operation-Name", Value: "__schema", Category: "WebSocket", Impact: "GraphQL Introspection Probe"},
		{Header: "X-GraphQL-Introspection", Value: "true", Category: "WebSocket", Impact: "GraphQL Introspection Enable"},

		// HTTP/2 Server Push
		{Header: "X-Push-Policy", Value: "full", Category: "WebSocket", Impact: "HTTP/2 Server Push Policy"},
	}
}
