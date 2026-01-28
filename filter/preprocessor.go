package filter

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type includeOptions struct {
	baseURL  string
	maxDepth int
}

const includeScannerMaxLine = 10 * 1024 * 1024 // 10MB

func expandIncludes(r io.Reader, opts includeOptions) (io.Reader, error) {
	if opts.maxDepth <= 0 {
		opts.maxDepth = 10
	}
	visited := map[string]struct{}{}
	return expandIncludesRecursive(r, opts, visited, 0)
}

func expandIncludesRecursive(r io.Reader, opts includeOptions, visited map[string]struct{}, depth int) (io.Reader, error) {
	if depth > opts.maxDepth {
		return nil, fmt.Errorf("include: max depth exceeded (%d)", opts.maxDepth)
	}

	base, err := normalizeBaseURL(opts.baseURL)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), includeScannerMaxLine)

	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)

		if !strings.HasPrefix(trimmed, "!#include") {
			out.WriteString(line)
			out.WriteByte('\n')
			continue
		}

		target := strings.TrimSpace(strings.TrimPrefix(trimmed, "!#include"))
		if target == "" {
			return nil, fmt.Errorf("include: empty !#include")
		}

		absURL, isAbs, err := resolveIncludeURL(base, target)
		if err != nil {
			return nil, err
		}

		if isAbs && base != nil && !sameHost(base, absURL) {
			return nil, fmt.Errorf("include: forbidden cross-origin include: %q (base %q)", absURL.String(), base.String())
		}

		key := absURL.String()
		if _, ok := visited[key]; ok {
			return nil, fmt.Errorf("include: recursive include detected: %q", key)
		}
		visited[key] = struct{}{}

		client := &http.Client{Timeout: 10 * time.Second}
		req, err := http.NewRequest(http.MethodGet, absURL.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("include: fetch %q: %w", key, err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("include: fetch %q: %w", key, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("include: fetch %q: non-200 response: %s", key, resp.Status)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("include: fetch %q: %w", key, err)
		}

		next := opts
		next.baseURL = key

		expanded, err := expandIncludesRecursive(bytes.NewReader(body), next, visited, depth+1)
		if err != nil {
			return nil, err
		}

		if _, err := io.Copy(&out, expanded); err != nil {
			return nil, fmt.Errorf("include: copy expanded %q: %w", key, err)
		}

		if out.Len() > 0 {
			b := out.Bytes()
			if b[len(b)-1] != '\n' {
				out.WriteByte('\n')
			}
		}

		delete(visited, key)
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("include: scan: %w", err)
	}

	return bytes.NewReader(out.Bytes()), nil
}

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
