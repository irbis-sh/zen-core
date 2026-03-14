package csp

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/ZenPrivacy/zen-core/httprewrite"
	"golang.org/x/net/html"
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
				if name, _ := z.TagName(); !bytes.Equal(name, []byte("meta")) {
					dst.Write(z.Raw())
					continue
				}

				tok := z.Token()

				var hasCSP bool
				contentInd := -1 // Track the index of the content= attribute.

				for i, a := range tok.Attr {
					if strings.EqualFold(a.Key, "http-equiv") &&
						strings.EqualFold(a.Val, "content-security-policy") {
						hasCSP = true
					}

					if strings.EqualFold(a.Key, "content") {
						contentInd = i
					}
				}

				if !hasCSP || contentInd == -1 || tok.Attr[contentInd].Val == "" {
					dst.Write(z.Raw())
					continue
				}

				// Apply all operations to this meta tag's CSP.
				var changed bool
				contentVal := tok.Attr[contentInd].Val
				patchedContent := contentVal

				for _, op := range operations {
					patched, patchChanged := patchPolicies([]string{patchedContent}, op.Nonce, op.Kind, op.ResourceURL)
					if patchChanged {
						patchedContent = patched[0]
						changed = true
					}
				}

				if !changed {
					dst.Write(z.Raw())
					continue
				}

				tok.Attr[contentInd].Val = patchedContent
				dst.Write([]byte(tok.String()))

			default:
				dst.Write(z.Raw())
			}
		}
	})

	return err
}
