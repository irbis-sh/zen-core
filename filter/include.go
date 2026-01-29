package filter

import (
	"fmt"
	"log"
	"net/url"
	"strings"
)

func resolveInclude(base *url.URL, currentURL string, after string) (includeURL string, ok bool) {
	target := strings.TrimSpace(after)
	if target == "" {
		log.Printf("include: empty !#include in %q", currentURL)
		return "", false
	}
	absURL, isAbs, err := resolveURL(base, target)
	if err != nil {
		log.Printf("include: resolve %q (base %q): %v", target, currentURL, err)
		return "", false
	}
	if isAbs && base != nil && !sameHost(base, absURL) {
		log.Printf("include: forbidden cross-origin include: %q (base %q)", absURL.String(), base.String())
		return "", false
	}
	return absURL.String(), true
}

func resolveURL(base *url.URL, raw string) (url *url.URL, isAbs bool, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, false, fmt.Errorf("include: invalid url/path %q: %w", raw, err)
	}

	if u.IsAbs() {
		return u, true, nil
	}

	if base == nil {
		return nil, false, fmt.Errorf("include: relative include %q but base url is empty", raw)
	}

	resolved := base.ResolveReference(u)
	return resolved, false, nil
}

func sameHost(a, b *url.URL) bool {
	return strings.EqualFold(a.Host, b.Host)
}
