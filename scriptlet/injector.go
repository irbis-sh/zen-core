package scriptlet

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/ZenPrivacy/zen-core/csp"
	"github.com/ZenPrivacy/zen-core/hostmatch"
	"github.com/ZenPrivacy/zen-core/httprewrite"
	"github.com/ZenPrivacy/zen-core/internal/redacted"
)

var (
	//go:embed bundle.js
	defaultScriptletsBundle []byte
)

type store interface {
	AddPrimaryRule(hostnamePatterns string, body argList) error
	AddExceptionRule(hostnamePatterns string, body argList) error
	Get(hostname string) []argList
}

// Injector injects scriptlets into HTML HTTP responses.
type Injector struct {
	// bundle contains the scriptlets JS bundle.
	bundle []byte
	// store stores and retrieves scriptlets by hostname.
	store store
}

func NewInjectorWithDefaults() (*Injector, error) {
	store := hostmatch.NewHostMatcher[argList]()
	return newInjector(defaultScriptletsBundle, store)
}

// newInjector creates a new Injector with the embedded scriptlets.
func newInjector(bundleData []byte, store store) (*Injector, error) {
	if bundleData == nil {
		return nil, errors.New("bundleData is nil")
	}
	if store == nil {
		return nil, errors.New("store is nil")
	}

	return &Injector{
		bundle: bundleData,
		store:  store,
	}, nil
}

// Inject injects scriptlets into a given HTTP HTML response.
//
// On error, the caller may proceed as if the function had not been called.
func (inj *Injector) Inject(req *http.Request, res *http.Response) error {
	hostname := req.URL.Hostname()
	argLists := inj.store.Get(hostname)
	log.Printf("got %d scriptlets for %q", len(argLists), redacted.Redacted(hostname))
	if len(argLists) == 0 {
		return nil
	}

	nonce, err := csp.PatchHeaders(res, csp.InlineScript)
	if err != nil {
		return fmt.Errorf("patch CSP headers: %w", err)
	}

	var injection bytes.Buffer
	injection.WriteString(`<script nonce="`)
	injection.WriteString(nonce)
	injection.WriteString(`">`)
	injection.Write(inj.bundle)
	injection.WriteString("(()=>{")
	for _, argLst := range argLists {
		if err := argLst.GenerateInjection(&injection); err != nil {
			return fmt.Errorf("generate injection for scriptlet %q: %v", argLst, err)
		}
	}
	injection.WriteString("})();</script>")

	// Appending the scriptlets bundle to the head of the document aligns with the behavior of uBlock Origin:
	// - https://github.com/gorhill/uBlock/blob/d7ae3a185eddeae0f12d07149c1f0ddd11fd0c47/platform/firefox/vapi-background-ext.js#L373-L375
	// - https://github.com/gorhill/uBlock/blob/d7ae3a185eddeae0f12d07149c1f0ddd11fd0c47/platform/chromium/vapi-background-ext.js#L223-L226
	if err := httprewrite.AppendHTMLHeadContents(res, injection.Bytes()); err != nil {
		return fmt.Errorf("append head contents: %w", err)
	}

	return nil
}
