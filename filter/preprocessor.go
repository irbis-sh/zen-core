package filter

import (
	"fmt"
	"net/url"
	"strings"
)

const includeScannerMaxLine = 10 * 1024 * 1024 // 10MB

func resolveIncludeURL(base *url.URL, raw string) (*url.URL, bool, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
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

func normalizeBaseURL(baseURL string) (*url.URL, error) {
	if baseURL == "" {
		return nil, nil
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("include: invalid base url %q: %w", baseURL, err)
	}
	return u, nil
}
