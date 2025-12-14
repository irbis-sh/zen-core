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

type inlineKind int

const (
	InlineScript inlineKind = iota
	InlineStyle
)

// PatchHeaders mutates CSP headers and meta tags so an inline <script> or <style>
// element can run. Returns the nonce to place on the inline tag.
// The nonce is safe to inject unconditionally.
func PatchHeaders(res *http.Response, kind inlineKind) (string, error) {
	if res == nil {
		return "", nil
	}

	nonce := newCSPNonce()

	err := patchMetaCSPs(res, nonce, kind)
	if err != nil {
		return "", fmt.Errorf("patch meta CSP: %w", err)
	}

	patchOneHeader(res.Header, cspHeader, nonce, kind)
	patchOneHeader(res.Header, cspReportOnly, nonce, kind)

	return nonce, nil
}

func patchOneHeader(h http.Header, key, nonce string, kind inlineKind) {
	lines := h.Values(key)
	if len(lines) == 0 {
		return
	}

	patchedLines, changed := patchPolicies(lines, nonce, kind)
	if changed {
		h.Del(key)
		for _, v := range patchedLines {
			h.Add(key, strings.TrimSpace(strings.Trim(v, " ;")))
		}
	}
}

func patchPolicies(policies []string, nonce string, kind inlineKind) ([]string, bool) {
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

		if allowsInline(kind, bestValue) {
			continue
		}

		var newValue string
		switch bestValue {
		case "'none'":
			newValue = nonceToken
		default:
			newValue = bestValue + " " + nonceToken
		}

		rawDirs[bestIdx] = bestName + " " + newValue
		policies[i] = strings.Join(rawDirs, ";")
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

// allowsInline implements CSP3 "Does a source list allow all inline behavior for type?" algorithm.
// True iff 'unsafe-inline' is present AND there is NO nonce/hash AND NO 'strict-dynamic'.
//
// Reference: https://www.w3.org/TR/CSP3/#allow-all-inline
func allowsInline(kind inlineKind, sourceList string) bool {
	sourceList = strings.TrimSpace(sourceList)
	if sourceList == "" {
		return false
	}
	tokens := strings.Fields(sourceList)

	var unsafeInline bool
	for _, t := range tokens {
		switch t {
		case "'unsafe-inline'":
			unsafeInline = true
		case "'strict-dynamic'":
			if kind == InlineScript {
				return false
			}
		default:
			if isNonceOrHashSource(t) {
				return false
			}
		}
	}
	return unsafeInline
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

func directivePriority(kind inlineKind, name string) int {
	switch kind {
	case InlineScript:
		switch name {
		case "script-src-elem":
			return 3
		case "script-src":
			return 2
		case "default-src":
			return 1
		}
	case InlineStyle:
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
