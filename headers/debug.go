package headers

import "github.com/cc1a2b/jshunter/engine"

func GetDebugMutations() []engine.Mutation {
	return []engine.Mutation{
		{Header: "X-Debug", Value: "true", Category: "Debug", Impact: "Debug Mode Enabled"},
		{Header: "X-Debug", Value: "1", Category: "Debug", Impact: "Debug Mode Enabled"},
		{Header: "X-Verbose", Value: "true", Category: "Debug", Impact: "Verbose Mode Enabled"},
		{Header: "X-Verbose", Value: "1", Category: "Debug", Impact: "Verbose Mode Enabled"},
		{Header: "X-Trace", Value: "enable", Category: "Debug", Impact: "Trace Mode Enabled"},
		{Header: "X-Trace", Value: "true", Category: "Debug", Impact: "Trace Mode Enabled"},
		{Header: "X-Profile", Value: "1", Category: "Debug", Impact: "Profiling Enabled"},
		{Header: "Debug", Value: "true", Category: "Debug", Impact: "Debug Mode Enabled"},
		{Header: "Verbose", Value: "true", Category: "Debug", Impact: "Verbose Mode Enabled"},
		{Header: "X-Developer-Mode", Value: "true", Category: "Debug", Impact: "Developer Mode Enabled"},
		{Header: "X-Testing", Value: "true", Category: "Debug", Impact: "Testing Mode Enabled"},
		{Header: "X-Test", Value: "true", Category: "Debug", Impact: "Test Mode Enabled"},
		{Header: "X-Show-Errors", Value: "1", Category: "Debug", Impact: "Error Display Enabled"},
		{Header: "X-Error-Details", Value: "full", Category: "Debug", Impact: "Full Error Details"},
		{Header: "X-Stack-Trace", Value: "true", Category: "Debug", Impact: "Stack Trace Enabled"},
		{Header: "X-Internal", Value: "true", Category: "Debug", Impact: "Internal Mode"},
		{Header: "X-Development", Value: "true", Category: "Debug", Impact: "Development Mode"},
		{Header: "X-Feature-Flag", Value: "admin", Category: "Debug", Impact: "Feature Flag Manipulation"},
		{Header: "X-Beta", Value: "true", Category: "Debug", Impact: "Beta Features Enabled"},
		{Header: "X-Experimental", Value: "true", Category: "Debug", Impact: "Experimental Features"},
	}
}
