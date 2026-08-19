package session

import (
	"fmt"
	"strings"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/hijack"
)

// hijackState holds the session-wide cookie injector shared with the proxy.
type hijackState struct {
	inj *hijack.Injector
}

// Injector returns the shared injector (created lazily).
func (s *Session) Injector() *hijack.Injector {
	// Guarded by the session mutex so concurrent REPL commands and proxy
	// goroutines never race on first-time initialization.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hijack == nil {
		s.hijack = &hijackState{inj: hijack.NewInjector()}
	}
	return s.hijack.inj
}

// sessionHijack manages cookie injection rules:
//
//	session.hijack add <victim-ip> [host=<host>] [cookie="name=value"] [header="K: V"]
//	session.hijack rm <victim-ip>
//	session.hijack show
func (s *Session) sessionHijack(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: session.hijack add|rm|show")
	}
	switch args[0] {
	case "add":
		return s.hijackAdd(args[1:])
	case "rm", "remove", "del":
		if len(args) < 2 {
			return fmt.Errorf("usage: session.hijack rm <victim-ip>")
		}
		s.Injector().Remove(args[1])
		_, _ = fmt.Fprintf(s.Out, "removed injection for %s\n", args[1])
	case "show", "list":
		// Render every rule with its optional host filter and injected
		// cookies/headers so the operator can review active injections.
		for _, r := range s.Injector().Rules() {
			_, _ = fmt.Fprintf(s.Out, "  %-18s host=%-24s cookies=%v headers=%v\n", r.VictimIP, r.Host, r.Cookies, r.Headers)
		}
	default:
		return fmt.Errorf("usage: session.hijack add|rm|show")
	}
	return nil
}

func (s *Session) hijackAdd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: session.hijack add <victim-ip> [host=<host>] [cookie=\"n=v\"] [header=\"K: V\"]")
	}
	// Start with empty cookie/header maps so the rule is always safe to
	// iterate over even if the user supplies no extra options.
	rule := hijack.CookieInjection{VictimIP: args[0], Cookies: map[string]string{}, Headers: map[string]string{}}
	for _, arg := range args[1:] {
		switch {
		case strings.HasPrefix(arg, "host="):
			// Optional host filter: the injection only applies to requests
			// whose Host header matches.
			rule.Host = strings.TrimPrefix(arg, "host=")
		case strings.HasPrefix(arg, "cookie="):
			// "cookie=name=value" splits on the first '=' after the prefix.
			kv := strings.TrimPrefix(arg, "cookie=")
			if i := strings.IndexByte(kv, '='); i > 0 {
				rule.Cookies[kv[:i]] = kv[i+1:]
			}
		case strings.HasPrefix(arg, "header="):
			// "header=K: V" splits on the first ':' and trims whitespace on
			// both sides of the header value.
			kv := strings.TrimPrefix(arg, "header=")
			if i := strings.IndexByte(kv, ':'); i > 0 {
				rule.Headers[strings.TrimSpace(kv[:i])] = strings.TrimSpace(kv[i+1:])
			}
		}
	}
	s.Injector().Add(rule)
	_, _ = fmt.Fprintf(s.Out, "injection added for %s\n", rule.VictimIP)
	return nil
}

// Ensure the session struct carries the injector.
var _ = attacks.Get
