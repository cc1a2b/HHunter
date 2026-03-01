package headers

import "github.com/cc1a2b/hhunter/engine"

func GetDebugMutations() []engine.Mutation {
	return []engine.Mutation{
		// Debug mode headers
		{Header: "X-Debug", Value: "true", Category: "Debug", Impact: "Debug Mode Enabled"},
		{Header: "X-Debug", Value: "1", Category: "Debug", Impact: "Debug Mode Enabled (numeric)"},
		{Header: "X-Debug", Value: "on", Category: "Debug", Impact: "Debug Mode Enabled (on)"},
		{Header: "X-Debug", Value: "verbose", Category: "Debug", Impact: "Debug Verbose Mode"},
		{Header: "X-Debug-Mode", Value: "true", Category: "Debug", Impact: "Debug Mode Header"},
		{Header: "X-Debug-Token", Value: "test", Category: "Debug", Impact: "Debug Token Probe"},
		{Header: "X-Debug-Token-Link", Value: "test", Category: "Debug", Impact: "Symfony Debug Token Link"},
		{Header: "Debug", Value: "true", Category: "Debug", Impact: "Debug Header (bare)"},
		{Header: "Debug", Value: "1", Category: "Debug", Impact: "Debug Header (bare numeric)"},

		// Verbose / Trace
		{Header: "X-Verbose", Value: "true", Category: "Debug", Impact: "Verbose Mode Enabled"},
		{Header: "X-Verbose", Value: "1", Category: "Debug", Impact: "Verbose Mode Enabled (numeric)"},
		{Header: "Verbose", Value: "true", Category: "Debug", Impact: "Verbose Header (bare)"},
		{Header: "X-Trace", Value: "enable", Category: "Debug", Impact: "Trace Mode Enabled"},
		{Header: "X-Trace", Value: "true", Category: "Debug", Impact: "Trace Mode (true)"},
		{Header: "X-Trace", Value: "1", Category: "Debug", Impact: "Trace Mode (numeric)"},
		{Header: "X-Trace-Id", Value: "test-trace", Category: "Debug", Impact: "Trace ID Injection"},
		{Header: "X-Profile", Value: "1", Category: "Debug", Impact: "Profiling Enabled"},
		{Header: "X-Profile", Value: "true", Category: "Debug", Impact: "Profiling Enabled (true)"},

		// Developer mode
		{Header: "X-Developer-Mode", Value: "true", Category: "Debug", Impact: "Developer Mode Enabled"},
		{Header: "X-Developer", Value: "true", Category: "Debug", Impact: "Developer Header"},
		{Header: "X-Dev-Mode", Value: "1", Category: "Debug", Impact: "Dev Mode (numeric)"},
		{Header: "X-Dev", Value: "true", Category: "Debug", Impact: "Dev Header"},

		// Testing mode
		{Header: "X-Testing", Value: "true", Category: "Debug", Impact: "Testing Mode Enabled"},
		{Header: "X-Test", Value: "true", Category: "Debug", Impact: "Test Mode Enabled"},
		{Header: "X-Test-Mode", Value: "1", Category: "Debug", Impact: "Test Mode (numeric)"},
		{Header: "X-Mock", Value: "true", Category: "Debug", Impact: "Mock Mode Enabled"},
		{Header: "X-Sandbox", Value: "true", Category: "Debug", Impact: "Sandbox Mode Enabled"},
		{Header: "X-Staging", Value: "true", Category: "Debug", Impact: "Staging Mode Enabled"},

		// Error exposure
		{Header: "X-Show-Errors", Value: "1", Category: "Debug", Impact: "Error Display Enabled"},
		{Header: "X-Show-Errors", Value: "true", Category: "Debug", Impact: "Error Display Enabled (true)"},
		{Header: "X-Error-Details", Value: "full", Category: "Debug", Impact: "Full Error Details"},
		{Header: "X-Error-Details", Value: "verbose", Category: "Debug", Impact: "Verbose Error Details"},
		{Header: "X-Stack-Trace", Value: "true", Category: "Debug", Impact: "Stack Trace Enabled"},
		{Header: "X-Backtrace", Value: "true", Category: "Debug", Impact: "Backtrace Enabled"},
		{Header: "X-Display-Errors", Value: "1", Category: "Debug", Impact: "PHP Display Errors"},
		{Header: "X-Php-Errors", Value: "verbose", Category: "Debug", Impact: "PHP Errors Verbose"},

		// Environment / deployment
		{Header: "X-Internal", Value: "true", Category: "Debug", Impact: "Internal Mode"},
		{Header: "X-Development", Value: "true", Category: "Debug", Impact: "Development Mode"},
		{Header: "X-Environment", Value: "development", Category: "Debug", Impact: "Environment Override - Dev"},
		{Header: "X-Environment", Value: "staging", Category: "Debug", Impact: "Environment Override - Staging"},
		{Header: "X-Environment", Value: "local", Category: "Debug", Impact: "Environment Override - Local"},
		{Header: "X-Env", Value: "dev", Category: "Debug", Impact: "Env Override - Dev"},
		{Header: "X-Env", Value: "debug", Category: "Debug", Impact: "Env Override - Debug"},
		{Header: "X-App-Env", Value: "development", Category: "Debug", Impact: "App Env Override"},
		{Header: "X-Runtime-Mode", Value: "debug", Category: "Debug", Impact: "Runtime Debug Mode"},

		// Feature flags
		{Header: "X-Feature-Flag", Value: "admin", Category: "Debug", Impact: "Feature Flag - Admin"},
		{Header: "X-Feature-Flag", Value: "debug", Category: "Debug", Impact: "Feature Flag - Debug"},
		{Header: "X-Feature-Flag", Value: "beta", Category: "Debug", Impact: "Feature Flag - Beta"},
		{Header: "X-Feature-Flags", Value: "admin,debug,beta", Category: "Debug", Impact: "Feature Flags - Multi"},
		{Header: "X-Beta", Value: "true", Category: "Debug", Impact: "Beta Features Enabled"},
		{Header: "X-Experimental", Value: "true", Category: "Debug", Impact: "Experimental Features"},
		{Header: "X-Canary", Value: "true", Category: "Debug", Impact: "Canary Deployment"},
		{Header: "X-Preview", Value: "true", Category: "Debug", Impact: "Preview Mode"},
		{Header: "X-Lab", Value: "true", Category: "Debug", Impact: "Lab Mode"},
		{Header: "X-Enable-Feature", Value: "all", Category: "Debug", Impact: "Enable All Features"},

		// Framework-specific debug
		{Header: "X-Laravel-Debug", Value: "true", Category: "Debug", Impact: "Laravel Debug Mode"},
		{Header: "X-Django-Debug", Value: "true", Category: "Debug", Impact: "Django Debug Mode"},
		{Header: "X-Rails-Env", Value: "development", Category: "Debug", Impact: "Rails Dev Environment"},
		{Header: "X-Symfony-Debug", Value: "1", Category: "Debug", Impact: "Symfony Debug Mode"},
		{Header: "X-Asp-Debug", Value: "true", Category: "Debug", Impact: "ASP.NET Debug Mode"},
		{Header: "X-Spring-Boot-Debug", Value: "true", Category: "Debug", Impact: "Spring Boot Debug"},
		{Header: "X-Express-Debug", Value: "true", Category: "Debug", Impact: "Express.js Debug"},
		{Header: "X-Flask-Debug", Value: "1", Category: "Debug", Impact: "Flask Debug Mode"},
		{Header: "X-Powered-By-Debug", Value: "true", Category: "Debug", Impact: "Powered-By Debug Mode"},

		// Diagnostic endpoints trigger
		{Header: "X-Diagnostic", Value: "true", Category: "Debug", Impact: "Diagnostic Mode"},
		{Header: "X-Health-Check", Value: "deep", Category: "Debug", Impact: "Deep Health Check"},
		{Header: "X-Ping", Value: "true", Category: "Debug", Impact: "Ping/Health Probe"},
		{Header: "X-Warmup", Value: "true", Category: "Debug", Impact: "Warmup Request"},
		{Header: "X-Readiness", Value: "true", Category: "Debug", Impact: "Readiness Probe"},
		{Header: "X-Liveness", Value: "true", Category: "Debug", Impact: "Liveness Probe"},

		// Admin / backdoor headers
		{Header: "X-Backdoor", Value: "true", Category: "Debug", Impact: "Backdoor Header Probe"},
		{Header: "X-God-Mode", Value: "true", Category: "Debug", Impact: "God Mode Header Probe"},
		{Header: "X-Master-Key", Value: "true", Category: "Debug", Impact: "Master Key Header Probe"},
		{Header: "X-Override-Auth", Value: "true", Category: "Debug", Impact: "Auth Override Header Probe"},
		{Header: "X-Skip-Auth", Value: "true", Category: "Debug", Impact: "Skip Auth Header Probe"},
		{Header: "X-Bypass-Auth", Value: "true", Category: "Debug", Impact: "Bypass Auth Header Probe"},
		{Header: "X-Disable-Auth", Value: "true", Category: "Debug", Impact: "Disable Auth Header Probe"},
		{Header: "X-No-Auth", Value: "true", Category: "Debug", Impact: "No Auth Header Probe"},
		{Header: "X-Skip-Validation", Value: "true", Category: "Debug", Impact: "Skip Validation Header Probe"},
		{Header: "X-Bypass-WAF", Value: "true", Category: "Debug", Impact: "Bypass WAF Header Probe"},
		{Header: "X-Disable-Rate-Limit", Value: "true", Category: "Debug", Impact: "Disable Rate Limit Header Probe"},
	}
}
