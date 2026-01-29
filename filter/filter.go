package filter

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/ZenPrivacy/zen-core/cosmetic"
	"github.com/ZenPrivacy/zen-core/cssrule"
	"github.com/ZenPrivacy/zen-core/extendedcss"
	"github.com/ZenPrivacy/zen-core/internal/redacted"
	"github.com/ZenPrivacy/zen-core/jsrule"
	"github.com/ZenPrivacy/zen-core/networkrules/rule"
	"github.com/ZenPrivacy/zen-core/scriptlet"
)

// filterEventsEmitter emits filter events.
type filterEventsEmitter interface {
	OnFilterBlock(method, url, referer string, rules []rule.Rule)
	OnFilterRedirect(method, url, to, referer string, rules []rule.Rule)
	OnFilterModify(method, url, referer string, rules []rule.Rule)
}

type httpClient interface {
	Get(url string) (*http.Response, error)
}

type networkRules interface {
	ParseRule(rule string, filterName *string) (isException bool, err error)
	ModifyReq(req *http.Request) (appliedRules []rule.Rule, shouldBlock bool, redirectURL string)
	ModifyRes(req *http.Request, res *http.Response) ([]rule.Rule, error)
	CreateBlockResponse(req *http.Request) *http.Response
	CreateRedirectResponse(req *http.Request, to string) *http.Response
	CreateBlockPageResponse(req *http.Request, appliedRules []rule.Rule, whitelistPort int) (*http.Response, error)
	Compact()
}

// scriptletsInjector injects scriptlets into HTML responses.
type scriptletsInjector interface {
	Inject(*http.Request, *http.Response) error
	AddRule(string, bool) error
}

type cosmeticRulesInjector interface {
	Inject(*http.Request, *http.Response) error
	AddRule(string) error
}

type cssRulesInjector interface {
	Inject(*http.Request, *http.Response) error
	AddRule(string) error
}

type jsRuleInjector interface {
	AddRule(rule string) error
	Inject(*http.Request, *http.Response) error
}

type extendedCSSInjector interface {
	AddRule(rule string) error
	Inject(*http.Request, *http.Response) error
}

type whitelistSrv interface {
	GetPort() int
}

// Filter is capable of parsing Adblock-style filter lists and hosts rules and matching URLs against them.
//
// Safe for concurrent use.
type Filter struct {
	networkRules          networkRules
	scriptletsInjector    scriptletsInjector
	cosmeticRulesInjector cosmeticRulesInjector
	cssRulesInjector      cssRulesInjector
	jsRuleInjector        jsRuleInjector
	extendedCSSInjector   extendedCSSInjector
	client                httpClient
	eventsEmitter         filterEventsEmitter
	whitelistSrv          whitelistSrv
}

var (
	// ignoreLineRegex matches comments and [Adblock Plus 2.0]-style headers.
	ignoreLineRegex = regexp.MustCompile(`^(?:!|\[|#[^#%@$])`)
)

// NewFilter creates and initializes a new filter.
func NewFilter(networkRules networkRules, scriptletsInjector scriptletsInjector, cosmeticRulesInjector cosmeticRulesInjector, cssRulesInjector cssRulesInjector, jsRuleInjector jsRuleInjector, extendedCSSInjector extendedCSSInjector, client httpClient, eventsEmitter filterEventsEmitter, whitelistSrv whitelistSrv) (*Filter, error) {
	if eventsEmitter == nil {
		return nil, errors.New("eventsEmitter is nil")
	}
	if networkRules == nil {
		return nil, errors.New("networkRules is nil")
	}
	if scriptletsInjector == nil {
		return nil, errors.New("scriptletsInjector is nil")
	}
	if cosmeticRulesInjector == nil {
		return nil, errors.New("cosmeticRulesInjector is nil")
	}
	if cssRulesInjector == nil {
		return nil, errors.New("cssRulesInjector is nil")
	}
	if jsRuleInjector == nil {
		return nil, errors.New("jsRuleInjector is nil")
	}
	if extendedCSSInjector == nil {
		return nil, errors.New("extendedCSSInjector is nil")
	}
	if client == nil {
		return nil, errors.New("client is nil")
	}
	if whitelistSrv == nil {
		return nil, errors.New("whitelistSrv is nil")
	}

	f := &Filter{
		networkRules:          networkRules,
		scriptletsInjector:    scriptletsInjector,
		cosmeticRulesInjector: cosmeticRulesInjector,
		cssRulesInjector:      cssRulesInjector,
		jsRuleInjector:        jsRuleInjector,
		extendedCSSInjector:   extendedCSSInjector,
		client:                client,
		eventsEmitter:         eventsEmitter,
		whitelistSrv:          whitelistSrv,
	}

	return f, nil
}

const includeMaxDepth = 20

// AddURL fetches a filter list from a URL, expands !#include directives, and adds rules to the filter.
func (f *Filter) AddURL(name string, urlStr string, trusted bool) error {
	if urlStr == "" {
		return errors.New("url is empty")
	}

	var ruleCount, exceptionCount int
	var countsMu sync.Mutex

	addRuleLine := func(line string) {
		if len(line) == 0 || ignoreLineRegex.MatchString(line) {
			return
		}
		if isException, err := f.addRule(line, &name, trusted); err != nil { // nolint:revive
			// log.Printf("error adding rule: %v", err)
		} else {
			countsMu.Lock()
			if isException {
				exceptionCount++
			} else {
				ruleCount++
			}
			countsMu.Unlock()
		}
	}

	visited := make(map[string]struct{})
	var visitedMu sync.Mutex

	var wg sync.WaitGroup
	var parseURL func(currentURL string, depth int)

	parseURL = func(currentURL string, depth int) {
		defer wg.Done()
		if depth > includeMaxDepth {
			log.Printf("filter: max depth %d exceeded when adding %q", includeMaxDepth, currentURL)
			return
		}

		visitedMu.Lock()
		if _, ok := visited[currentURL]; ok {
			visitedMu.Unlock()
			log.Printf("filter: duplicate include %q skipped", currentURL)
			return
		}
		visited[currentURL] = struct{}{}
		visitedMu.Unlock()

		resp, err := f.client.Get(currentURL)
		if err != nil {
			log.Printf("filter: error getting %q: %v", currentURL, err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("filter: failed to fetch %q with non-200 response: %s", currentURL, resp.Status)
			return
		}

		base, err := url.Parse(currentURL)
		if err != nil {
			log.Printf("filter: error parsing url %q: %v", currentURL, err)
			return
		}

		scanner := bufio.NewScanner(resp.Body)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if after, ok := strings.CutPrefix(line, "!#include"); ok {
				includeURL, err := resolveInclude(base, after)
				if err != nil {
					log.Printf("filter: error resolving include: %v", err)
					continue
				}

				wg.Add(1)
				go parseURL(includeURL, depth+1)
				continue
			}

			addRuleLine(line)
		}
		if err := scanner.Err(); err != nil {
			log.Printf("filter: error scanning %q: %v", currentURL, err)
		}
	}

	wg.Add(1)
	go parseURL(urlStr, 0)
	wg.Wait()

	log.Printf("filter: added %d rules, %d exceptions from %s", ruleCount, exceptionCount, name)
	return nil
}

// AddReader parses the rules from the given reader and adds them to the filter.
func (f *Filter) AddReader(name string, trusted bool, rules io.Reader) error {
	var ruleCount, exceptionCount int
	scanner := bufio.NewScanner(rules)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || ignoreLineRegex.MatchString(line) {
			continue
		}

		if isException, err := f.addRule(line, &name, trusted); err != nil { // nolint:revive
			// log.Printf("error adding rule: %v", err)
		} else if isException {
			exceptionCount++
		} else {
			ruleCount++
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	log.Printf("filter: added %d rules, %d exceptions from %s", ruleCount, exceptionCount, name)
	return nil
}

// addRule adds a new rule to the filter.
func (f *Filter) addRule(rule string, filterListName *string, filterListTrusted bool) (isException bool, err error) {
	/*
		The order of operations here is critical:
			- jsRule.RuleRegex matches a superset of scriptlet.RuleRegex.
			- extendedcss.IsRule matches a superset of cosmetic.IsRule.

		The more specific rules must be checked first to avoid misclassification.
	*/
	switch {
	case scriptlet.RuleRegex.MatchString(rule):
		if err := f.scriptletsInjector.AddRule(rule, filterListTrusted); err != nil {
			return false, fmt.Errorf("add scriptlet: %w", err)
		}
	case cosmetic.IsRule(rule):
		if err := f.cosmeticRulesInjector.AddRule(rule); err != nil {
			return false, fmt.Errorf("add cosmetic rule: %w", err)
		}
	case extendedcss.IsRule(rule):
		if err := f.extendedCSSInjector.AddRule(rule); err != nil {
			return false, fmt.Errorf("add extended css rule: %w", err)
		}
	case filterListTrusted && cssrule.RuleRegex.MatchString(rule):
		if err := f.cssRulesInjector.AddRule(rule); err != nil {
			return false, fmt.Errorf("add css rule: %w", err)
		}
	case filterListTrusted && jsrule.RuleRegex.MatchString(rule):
		if err := f.jsRuleInjector.AddRule(rule); err != nil {
			return false, fmt.Errorf("add js rule: %w", err)
		}
	default:
		isExceptionRule, err := f.networkRules.ParseRule(rule, filterListName)
		if err != nil {
			return false, fmt.Errorf("parse network rule: %w", err)
		}
		return isExceptionRule, nil
	}

	return false, nil
}

// HandleRequest handles the given request by matching it against the filter rules.
// If the request should be blocked, it returns a response that blocks the request. If the request should be modified, it modifies it in-place.
func (f *Filter) HandleRequest(req *http.Request) (*http.Response, error) {
	initialURL := req.URL.String()

	appliedRules, shouldBlock, redirectURL := f.networkRules.ModifyReq(req)
	if shouldBlock {
		f.eventsEmitter.OnFilterBlock(req.Method, initialURL, req.Header.Get("Referer"), appliedRules)

		if isUserNavigation(req) {
			port := f.whitelistSrv.GetPort()
			if port <= 0 {
				log.Printf("whitelist server not ready, falling back to simple block response for %q", redacted.Redacted(req.URL))
				return f.networkRules.CreateBlockResponse(req), nil
			}

			res, err := f.networkRules.CreateBlockPageResponse(req, appliedRules, f.whitelistSrv.GetPort())
			if err != nil {
				return nil, fmt.Errorf("create block page response: %v", err)
			}
			return res, nil
		}
		return f.networkRules.CreateBlockResponse(req), nil
	}

	if redirectURL != "" {
		f.eventsEmitter.OnFilterRedirect(req.Method, initialURL, redirectURL, req.Header.Get("Referer"), appliedRules)
		return f.networkRules.CreateRedirectResponse(req, redirectURL), nil
	}

	if len(appliedRules) > 0 {
		f.eventsEmitter.OnFilterModify(req.Method, initialURL, req.Header.Get("Referer"), appliedRules)
	}

	return nil, nil
}

// Finalize optimizes internal data structures after all filter lists have been loaded.
// This method should be called once after all AddURL/AddReader calls are complete and before
// the filter starts handling requests. Calling Finalize is not required for correctness,
// but improves memory usage and lookup performance.
func (f *Filter) Finalize() {
	f.networkRules.Compact()
}

// HandleResponse handles the given response by matching it against the filter rules.
// If the response should be modified, it modifies it in-place.
//
// As of April 2024, there are no response-only rules that can block or redirect responses.
// For that reason, this method does not return a blocking or redirecting response itself.
func (f *Filter) HandleResponse(req *http.Request, res *http.Response) error {
	if isDocumentNavigation(req, res) {
		if err := f.scriptletsInjector.Inject(req, res); err != nil {
			// This and the following injection errors are recoverable, so we log them and continue processing the response.
			log.Printf("error injecting scriptlets for %q: %v", redacted.Redacted(req.URL), err)
		}

		if err := f.cosmeticRulesInjector.Inject(req, res); err != nil {
			log.Printf("error injecting cosmetic rules for %q: %v", redacted.Redacted(req.URL), err)
		}
		if err := f.extendedCSSInjector.Inject(req, res); err != nil {
			log.Printf("error injecting extended-css rules for %q: %v", redacted.Redacted(req.URL), err)
		}
		if err := f.cssRulesInjector.Inject(req, res); err != nil {
			log.Printf("error injecting css rules for %q: %v", redacted.Redacted(req.URL), err)
		}
		if err := f.jsRuleInjector.Inject(req, res); err != nil {
			log.Printf("error injecting js rules for %q: %v", redacted.Redacted(req.URL), err)
		}
	}

	appliedRules, err := f.networkRules.ModifyRes(req, res)
	if err != nil {
		return fmt.Errorf("apply network rules: %v", err)
	}
	if len(appliedRules) > 0 {
		f.eventsEmitter.OnFilterModify(req.Method, req.URL.String(), req.Header.Get("Referer"), appliedRules)
	}

	return nil
}

func isDocumentNavigation(req *http.Request, res *http.Response) bool {
	// Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Dest#directives
	// Note: Although not explicitly stated in the spec, Fetch Metadata Request Headers are only included in requests sent to HTTPS endpoints.
	if req.URL.Scheme == "https" {
		secFetchDest := req.Header.Get("Sec-Fetch-Dest")
		if secFetchDest != "document" && secFetchDest != "iframe" {
			return false
		}
	}

	contentType := res.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	if mediaType != "text/html" {
		return false
	}

	return true
}

func isUserNavigation(req *http.Request) bool {
	dest := req.Header.Get("Sec-Fetch-Dest")
	mode := req.Header.Get("Sec-Fetch-Mode")
	user := req.Header.Get("Sec-Fetch-User")

	if dest == "document" && (mode == "navigate" || user == "?1") {
		return true
	}
	return false
}
