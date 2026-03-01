package engine

import (
	"fmt"
	"strings"
)

// ChainEngine generates and tests multi-header mutation combinations.
// Instead of testing headers one at a time, it combines compatible
// mutations to discover vulnerabilities that only manifest with
// specific header combinations.

// ChainedMutation represents a group of headers sent together
type ChainedMutation struct {
	Headers  map[string]string // header -> value
	Category string
	Impact   string
	Source   []Mutation // original mutations that form this chain
}

// GenerateChains creates intelligent multi-header combinations
// from a set of mutations. Returns ChainedMutations grouped by attack strategy.
func GenerateChains(mutations []Mutation, maxChainSize int) []ChainedMutation {
	if maxChainSize < 2 {
		maxChainSize = 2
	}
	if maxChainSize > 4 {
		maxChainSize = 4
	}

	var chains []ChainedMutation

	// Group mutations by category for strategic pairing
	byCategory := groupByCategory(mutations)

	// Strategy 1: Auth bypass combos — combine multiple auth headers
	chains = append(chains, generateAuthChains(byCategory)...)

	// Strategy 2: Proxy chain — combine IP spoofing with host override
	chains = append(chains, generateProxyChains(byCategory)...)

	// Strategy 3: Cache poisoning — combine host injection with cache headers
	chains = append(chains, generateCachePoisonChains(byCategory)...)

	// Strategy 4: WAF bypass combos — combine encoding tricks with payloads
	chains = append(chains, generateWAFBypassChains(byCategory)...)

	// Strategy 5: CORS + Auth — test if CORS breaks with auth bypass
	chains = append(chains, generateCORSAuthChains(byCategory)...)

	// Strategy 6: Smuggling combos — combine CL/TE manipulation
	chains = append(chains, generateSmugglingChains(byCategory)...)

	// Strategy 7: Cross-category high-value combos
	chains = append(chains, generateCrossCategoryChains(byCategory)...)

	return chains
}

// ChainedToMutations converts chained mutations to flat Mutation structs
// for the orchestrator. The first header becomes the primary, rest go in headers map.
func ChainedToMutations(chains []ChainedMutation) []Mutation {
	var mutations []Mutation

	for _, chain := range chains {
		// Create a combined header string for display
		var headerParts []string
		var valueParts []string
		for h, v := range chain.Headers {
			headerParts = append(headerParts, h)
			valueParts = append(valueParts, h+": "+v)
		}

		mutations = append(mutations, Mutation{
			Header:   strings.Join(headerParts, " + "),
			Value:    strings.Join(valueParts, " | "),
			Category: chain.Category,
			Impact:   chain.Impact,
		})
	}

	return mutations
}

func groupByCategory(mutations []Mutation) map[string][]Mutation {
	groups := make(map[string][]Mutation)
	for _, m := range mutations {
		groups[m.Category] = append(groups[m.Category], m)
	}
	return groups
}

func generateAuthChains(byCategory map[string][]Mutation) []ChainedMutation {
	var chains []ChainedMutation

	authMuts := byCategory["Auth"]
	proxyMuts := byCategory["Proxy"]

	if len(authMuts) == 0 {
		return chains
	}

	// Combine top auth mutations with top proxy mutations (IP + auth header)
	topAuth := selectTopMutations(authMuts, 5)
	topProxy := selectTopMutations(proxyMuts, 3)

	for _, auth := range topAuth {
		for _, proxy := range topProxy {
			if auth.Header == proxy.Header {
				continue
			}
			chains = append(chains, ChainedMutation{
				Headers: map[string]string{
					auth.Header:  auth.Value,
					proxy.Header: proxy.Value,
				},
				Category: "Auth",
				Impact:   fmt.Sprintf("Auth bypass chain: %s + %s", auth.Header, proxy.Header),
				Source:   []Mutation{auth, proxy},
			})
		}
	}

	// Combine auth headers with override headers
	overrideMuts := byCategory["Override"]
	topOverride := selectTopMutations(overrideMuts, 3)

	for _, auth := range topAuth {
		for _, ovr := range topOverride {
			if auth.Header == ovr.Header {
				continue
			}
			chains = append(chains, ChainedMutation{
				Headers: map[string]string{
					auth.Header: auth.Value,
					ovr.Header:  ovr.Value,
				},
				Category: "Auth",
				Impact:   fmt.Sprintf("Auth bypass + method override: %s + %s", auth.Header, ovr.Header),
				Source:   []Mutation{auth, ovr},
			})
		}
	}

	return chains
}

func generateProxyChains(byCategory map[string][]Mutation) []ChainedMutation {
	var chains []ChainedMutation

	proxyMuts := byCategory["Proxy"]
	if len(proxyMuts) < 2 {
		return chains
	}

	// Common pattern: send X-Forwarded-For AND X-Real-IP together
	ipHeaders := map[string]bool{
		"X-Forwarded-For": true, "X-Real-IP": true, "X-Client-IP": true,
		"X-Originating-IP": true, "True-Client-IP": true, "CF-Connecting-IP": true,
	}

	hostHeaders := map[string]bool{
		"X-Forwarded-Host": true, "X-Host": true, "X-Original-Host": true,
		"X-Forwarded-Server": true,
	}

	var ipMuts, hostMuts []Mutation
	for _, m := range proxyMuts {
		if ipHeaders[m.Header] {
			ipMuts = append(ipMuts, m)
		}
		if hostHeaders[m.Header] {
			hostMuts = append(hostMuts, m)
		}
	}

	// Combine IP spoofing with host override
	topIP := selectTopMutations(ipMuts, 3)
	topHost := selectTopMutations(hostMuts, 2)

	for _, ip := range topIP {
		for _, host := range topHost {
			chains = append(chains, ChainedMutation{
				Headers: map[string]string{
					ip.Header:   ip.Value,
					host.Header: host.Value,
				},
				Category: "Proxy",
				Impact:   fmt.Sprintf("IP spoof + Host override: %s + %s", ip.Header, host.Header),
				Source:   []Mutation{ip, host},
			})
		}
	}

	return chains
}

func generateCachePoisonChains(byCategory map[string][]Mutation) []ChainedMutation {
	var chains []ChainedMutation

	cacheMuts := byCategory["Cache"]
	if len(cacheMuts) == 0 {
		return chains
	}

	// Combine cache mutations with injection/XSS payloads
	injectionMuts := byCategory["Injection"]
	topCache := selectTopMutations(cacheMuts, 3)
	topInjection := selectTopMutations(injectionMuts, 2)

	for _, cache := range topCache {
		for _, inj := range topInjection {
			if cache.Header == inj.Header {
				continue
			}
			chains = append(chains, ChainedMutation{
				Headers: map[string]string{
					cache.Header: cache.Value,
					inj.Header:   inj.Value,
				},
				Category: "Cache",
				Impact:   fmt.Sprintf("Cache poisoning + injection: %s + %s", cache.Header, inj.Header),
				Source:   []Mutation{cache, inj},
			})
		}
	}

	return chains
}

func generateWAFBypassChains(byCategory map[string][]Mutation) []ChainedMutation {
	var chains []ChainedMutation

	contentTypeMuts := byCategory["ContentType"]
	encodingMuts := byCategory["Encoding"]
	injectionMuts := byCategory["Injection"]

	if len(injectionMuts) == 0 {
		return chains
	}

	// Combine Content-Type confusion with injection payloads
	topCT := selectTopMutations(contentTypeMuts, 2)
	topInj := selectTopMutations(injectionMuts, 3)

	for _, ct := range topCT {
		for _, inj := range topInj {
			if ct.Header == inj.Header {
				continue
			}
			chains = append(chains, ChainedMutation{
				Headers: map[string]string{
					ct.Header:  ct.Value,
					inj.Header: inj.Value,
				},
				Category: "Injection",
				Impact:   fmt.Sprintf("WAF bypass via Content-Type + injection: %s + %s", ct.Header, inj.Header),
				Source:   []Mutation{ct, inj},
			})
		}
	}

	// Combine encoding tricks with injection payloads
	topEnc := selectTopMutations(encodingMuts, 2)
	for _, enc := range topEnc {
		for _, inj := range topInj {
			if enc.Header == inj.Header {
				continue
			}
			chains = append(chains, ChainedMutation{
				Headers: map[string]string{
					enc.Header: enc.Value,
					inj.Header: inj.Value,
				},
				Category: "Injection",
				Impact:   fmt.Sprintf("WAF bypass via encoding + injection: %s + %s", enc.Header, inj.Header),
				Source:   []Mutation{enc, inj},
			})
		}
	}

	return chains
}

func generateCORSAuthChains(byCategory map[string][]Mutation) []ChainedMutation {
	var chains []ChainedMutation

	corsMuts := byCategory["CORS"]
	authMuts := byCategory["Auth"]

	if len(corsMuts) == 0 || len(authMuts) == 0 {
		return chains
	}

	topCORS := selectTopMutations(corsMuts, 2)
	topAuth := selectTopMutations(authMuts, 2)

	for _, cors := range topCORS {
		for _, auth := range topAuth {
			chains = append(chains, ChainedMutation{
				Headers: map[string]string{
					cors.Header: cors.Value,
					auth.Header: auth.Value,
				},
				Category: "CORS",
				Impact:   fmt.Sprintf("CORS + Auth bypass: %s + %s", cors.Header, auth.Header),
				Source:   []Mutation{cors, auth},
			})
		}
	}

	return chains
}

func generateSmugglingChains(byCategory map[string][]Mutation) []ChainedMutation {
	var chains []ChainedMutation

	smugMuts := byCategory["Smuggling"]
	hopMuts := byCategory["HopByHop"]

	if len(smugMuts) == 0 {
		return chains
	}

	// Combine smuggling with hop-by-hop stripping
	topSmug := selectTopMutations(smugMuts, 3)
	topHop := selectTopMutations(hopMuts, 2)

	for _, smug := range topSmug {
		for _, hop := range topHop {
			if smug.Header == hop.Header {
				continue
			}
			chains = append(chains, ChainedMutation{
				Headers: map[string]string{
					smug.Header: smug.Value,
					hop.Header:  hop.Value,
				},
				Category: "Smuggling",
				Impact:   fmt.Sprintf("Smuggling + hop-by-hop: %s + %s", smug.Header, hop.Header),
				Source:   []Mutation{smug, hop},
			})
		}
	}

	return chains
}

func generateCrossCategoryChains(byCategory map[string][]Mutation) []ChainedMutation {
	var chains []ChainedMutation

	// Gateway bypass + Auth bypass
	gatewayMuts := byCategory["Gateway"]
	authMuts := byCategory["Auth"]

	if len(gatewayMuts) > 0 && len(authMuts) > 0 {
		topGW := selectTopMutations(gatewayMuts, 2)
		topAuth := selectTopMutations(authMuts, 2)

		for _, gw := range topGW {
			for _, auth := range topAuth {
				if gw.Header == auth.Header {
					continue
				}
				chains = append(chains, ChainedMutation{
					Headers: map[string]string{
						gw.Header:   gw.Value,
						auth.Header: auth.Value,
					},
					Category: "Gateway",
					Impact:   fmt.Sprintf("Gateway bypass + Auth: %s + %s", gw.Header, auth.Header),
					Source:   []Mutation{gw, auth},
				})
			}
		}
	}

	// Debug + Cloud (enable debug on cloud infra)
	debugMuts := byCategory["Debug"]
	cloudMuts := byCategory["Cloud"]

	if len(debugMuts) > 0 && len(cloudMuts) > 0 {
		topDebug := selectTopMutations(debugMuts, 2)
		topCloud := selectTopMutations(cloudMuts, 2)

		for _, dbg := range topDebug {
			for _, cloud := range topCloud {
				if dbg.Header == cloud.Header {
					continue
				}
				chains = append(chains, ChainedMutation{
					Headers: map[string]string{
						dbg.Header:   dbg.Value,
						cloud.Header: cloud.Value,
					},
					Category: "Debug",
					Impact:   fmt.Sprintf("Debug + Cloud: %s + %s", dbg.Header, cloud.Header),
					Source:   []Mutation{dbg, cloud},
				})
			}
		}
	}

	// Protocol + Smuggling (HTTP/2 downgrade + smuggling)
	protocolMuts := byCategory["Protocol"]
	smugMuts := byCategory["Smuggling"]

	if len(protocolMuts) > 0 && len(smugMuts) > 0 {
		topProto := selectTopMutations(protocolMuts, 2)
		topSmug := selectTopMutations(smugMuts, 2)

		for _, proto := range topProto {
			for _, smug := range topSmug {
				if proto.Header == smug.Header {
					continue
				}
				chains = append(chains, ChainedMutation{
					Headers: map[string]string{
						proto.Header: proto.Value,
						smug.Header:  smug.Value,
					},
					Category: "Smuggling",
					Impact:   fmt.Sprintf("Protocol downgrade + Smuggling: %s + %s", proto.Header, smug.Header),
					Source:   []Mutation{proto, smug},
				})
			}
		}
	}

	return chains
}

// selectTopMutations picks the most impactful mutations from a category
// Prioritizes mutations with diverse headers to maximize coverage
func selectTopMutations(mutations []Mutation, n int) []Mutation {
	if len(mutations) <= n {
		return mutations
	}

	// Deduplicate by header name — pick one payload per unique header
	seen := make(map[string]bool)
	var selected []Mutation

	for _, m := range mutations {
		if !seen[m.Header] && len(selected) < n {
			seen[m.Header] = true
			selected = append(selected, m)
		}
	}

	// If we still need more, add from unseen
	if len(selected) < n {
		for _, m := range mutations {
			if len(selected) >= n {
				break
			}
			if !seen[m.Header+m.Value] {
				seen[m.Header+m.Value] = true
				selected = append(selected, m)
			}
		}
	}

	return selected
}
