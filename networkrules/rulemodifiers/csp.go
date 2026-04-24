package rulemodifiers

import (
	"errors"
	"net/http"
	"strings"
)

type CSPModifier struct {
	policy string
}

var _ ModifyingModifier = (*CSPModifier)(nil)

func (m *CSPModifier) Parse(modifier string) error {
	if !strings.HasPrefix(modifier, "csp=") {
		return errors.New("invalid csp modifier")
	}
	m.policy = strings.TrimPrefix(modifier, "csp=")
	if m.policy == "" {
		return errors.New("empty csp policy")
	}
	return nil
}

func (m *CSPModifier) ModifyReq(req *http.Request) bool {
	// CSP is a response header, so we do nothing to the request.
	return false
}

func (m *CSPModifier) ModifyRes(res *http.Response) (bool, error) {
	// We use Add() instead of Set() because if the site already has a CSP,
	// browsers enforce the "intersection" of all policies (most restrictive wins).
	res.Header.Add("Content-Security-Policy", m.policy)
	return true, nil
}

func (m *CSPModifier) Cancels(modifier Modifier) bool {
	other, ok := modifier.(*CSPModifier)
	if !ok {
		return false
	}
	return m.policy == other.policy
}
