package csp

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

const (
	cspHeader     = "Content-Security-Policy"
	cspReportOnly = "Content-Security-Policy-Report-Only"
)

type tagKind int

const (
	Script tagKind = iota
	Style
)

// PatchHeaders mutates CSP headers and meta tags so a remote <script> or <link>
// element can load. Returns a nonce to place on the element.
func PatchHeaders(res *http.Response, kind tagKind, resourceURL string) (string, error) {
	if res == nil {
		return "", nil
	}

	nonce := newCSPNonce()

	err := patchMetaCSPs(res, nonce, kind, resourceURL)
	if err != nil {
		return "", fmt.Errorf("patch meta CSP: %w", err)
	}

	patchOneHeader(res.Header, cspHeader, nonce, kind, resourceURL)
	patchOneHeader(res.Header, cspReportOnly, nonce, kind, resourceURL)

	return nonce, nil
}

func patchOneHeader(h http.Header, key, nonce string, kind tagKind, resourceURL string) {
	lines := h.Values(key)
	if len(lines) == 0 {
		return
	}

	patchedLines, changed := patchPolicies(lines, nonce, kind, resourceURL)
	if changed {
		h.Del(key)
		for _, v := range patchedLines {
			h.Add(key, strings.TrimSpace(strings.Trim(v, " ;")))
		}
	}
}

func patchPolicies(policies []string, nonce string, kind tagKind, resourceURL string) ([]string, bool) {
	if len(policies) == 0 {
		return policies, false
	}

	nonceToken := "'nonce-" + nonce + "'"
	changed := false
	// In case of multiple lines/policies, the browsers will select the most restrictive one.
	// For this reason, we modify each independently so they all allow the inline tag.
	// See more: https://content-security-policy.com/examples/multiple-csp-headers/.
	for i, line := range policies {
		rawDirs := strings.Split(line, ";")
		// Find the most specific directive governing this kind on this line/policy.
		bestIdx, bestName, bestPrio, bestValue := -1, "", 0, ""
		for j, raw := range rawDirs {
			d := strings.TrimSpace(raw)
			if d == "" {
				continue
			}
			name, value := cutDirective(d)
			if prio := directivePriority(kind, name); prio > bestPrio {
				bestIdx, bestName, bestPrio, bestValue = j, name, prio, value
			}
		}
		// No relevant directive on this line; leave it as-is.
		if bestIdx == -1 {
			continue
		}

		var appendValue string
		switch safeNonce(bestValue) {
		case true:
			appendValue = nonceToken
		case false:
			appendValue = resourceURL
		}

		newValue := appendToken(bestValue, appendValue)
		rawDirs[bestIdx] = bestName + " " + newValue
		policies[i] = strings.Join(rawDirs, "; ")
		changed = true
	}

	if changed {
		for i, policy := range policies {
			policies[i] = strings.TrimSpace(strings.Trim(policy, " ;"))
		}
	}

	return policies, changed
}

// cutDirective splits "name [value...]" -> (lowercased name, value without leading and trailing whitespace).
func cutDirective(s string) (string, string) {
	name, rest, ok := strings.Cut(s, " ")
	if !ok {
		return strings.ToLower(name), ""
	}
	return strings.ToLower(name), strings.TrimSpace(rest)
}

// newCSPNonce returns a cryptographically random base64 string.
func newCSPNonce() string {
	// From https://www.w3.org/TR/CSP3/#security-nonces:
	// The generated value SHOULD be at least 128 bits long (before encoding), and
	// SHOULD be generated via a cryptographically secure random number generator in order to ensure that the value is difficult for an attacker to predict.
	// The code below satisfies both of these requirements.
	var b [18]byte // 144 bits
	rand.Read(b[:])
	return base64.StdEncoding.EncodeToString(b[:])
}

// safeNonce checks if it's safe to inject a nonce into the source list.
func safeNonce(sourceList string) bool {
	// - https://www.w3.org/TR/CSP3/#allow-all-inline
	// - https://www.w3.org/TR/CSP3/#strict-dynamic-usage
	var hasUnsafeInline bool
	for _, t := range strings.Fields(sourceList) {
		if isNonceOrHashSource(t) || t == "'strict-dynamic'" {
			return true
		}
		if t == "'unsafe-inline'" {
			hasUnsafeInline = true
		}
	}
	return !hasUnsafeInline
}

func isNonceOrHashSource(t string) bool {
	if len(t) < 3 || t[0] != '\'' || t[len(t)-1] != '\'' {
		return false
	}
	inner := t[1 : len(t)-1]
	return strings.HasPrefix(inner, "nonce-") ||
		strings.HasPrefix(inner, "sha256-") ||
		strings.HasPrefix(inner, "sha384-") ||
		strings.HasPrefix(inner, "sha512-")
}

func appendToken(sourceList, token string) string {
	sourceList = strings.TrimSpace(sourceList)
	if sourceList == "" || sourceList == "'none'" {
		return token
	}
	return sourceList + " " + token
}

func directivePriority(kind tagKind, name string) int {
	switch kind {
	case Script:
		switch name {
		case "script-src-elem":
			return 3
		case "script-src":
			return 2
		case "default-src":
			return 1
		}
	case Style:
		switch name {
		case "style-src-elem":
			return 3
		case "style-src":
			return 2
		case "default-src":
			return 1
		}
	}
	return 0
}
