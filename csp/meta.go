package csp

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/ZenPrivacy/zen-core/httprewrite"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// patchMetaCSPsBatch mutates HTML <meta> tags for multiple CSP operations in a single pass.
func patchMetaCSPsBatch(res *http.Response, operations []PatchOperation) error {
	if res.Body == nil || res.Body == http.NoBody {
		return nil
	}

	err := httprewrite.StreamRewrite(res, func(src io.ReadCloser, dst *io.PipeWriter) {
		defer src.Close()

		z := html.NewTokenizer(src)
		for {
			tt := z.Next()
			switch tt {
			case html.ErrorToken:
				dst.CloseWithError(z.Err())
				return

			case html.StartTagToken, html.SelfClosingTagToken:
				raw := append([]byte{}, z.Raw()...)
				tok := z.Token()
				if tok.DataAtom != atom.Meta {
					dst.Write(raw)
					continue
				}

				var hasCSP bool
				var contentVal string

				for _, a := range tok.Attr {
					if strings.EqualFold(a.Key, "http-equiv") &&
						strings.EqualFold(a.Val, "content-security-policy") {
						hasCSP = true
					}

					if strings.EqualFold(a.Key, "content") {
						contentVal = a.Val
					}
				}

				if !hasCSP || contentVal == "" {
					dst.Write(raw)
					continue
				}

				// Apply all operations to this meta tag's CSP
				patchedContent := contentVal
				changed := false
				for _, op := range operations {
					patched, patchChanged := patchPolicies([]string{patchedContent}, op.Nonce, op.Kind, op.ResourceURL)
					if patchChanged {
						patchedContent = patched[0]
						changed = true
					}
				}

				if !changed {
					dst.Write(raw)
					continue
				}

				patchedRaw := replaceContentValue(raw, patchedContent)
				dst.Write(patchedRaw)

			default:
				dst.Write(z.Raw())
			}
		}
	})

	return err
}

func replaceContentValue(raw []byte, newVal string) []byte {
	lower := bytes.ToLower(raw)
	i := bytes.Index(lower, []byte("content="))

	if i == -1 {
		return raw
	}

	afterKey := raw[i+len("content="):]
	if len(afterKey) == 0 {
		return raw
	}

	quote := afterKey[0]
	if quote != '"' && quote != '\'' {
		return raw
	}

	valueStart := i + len("content=") + 1
	valueEndRel := bytes.IndexByte(raw[valueStart:], quote)
	if valueEndRel == -1 {
		return raw
	}
	valueEnd := valueStart + valueEndRel

	out := make([]byte, 0, valueStart+len(newVal)+(len(raw)-valueEnd))
	out = append(out, raw[:valueStart]...)
	out = append(out, newVal...)
	out = append(out, raw[valueEnd:]...)
	return out
}
