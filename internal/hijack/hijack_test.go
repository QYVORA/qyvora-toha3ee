package hijack

import (
	"net/http"
	"testing"
)

func TestInjectorLifecycle(t *testing.T) {
	inj := NewInjector()
	rule := CookieInjection{
		VictimIP: "10.0.0.5",
		Host:     "bank.com",
		Cookies:  map[string]string{"session": "abc"},
		Headers:  map[string]string{"X-Real-IP": "10.0.0.5"},
	}
	inj.Add(rule)

	r, ok := inj.Rule("10.0.0.5")
	if !ok || r.Cookies["session"] != "abc" {
		t.Fatal("rule not stored")
	}

	var cookies, headers []string
	inj.Apply("10.0.0.5", "bank.com", func(n, v string) { cookies = append(cookies, n+"="+v) }, func(k, _ string) { headers = append(headers, k) })
	if len(cookies) != 1 || len(headers) != 1 {
		t.Fatalf("apply wrong: cookies=%v headers=%v", cookies, headers)
	}

	// Host filter: different host -> no injection.
	cookies = nil
	inj.Apply("10.0.0.5", "other.com", func(n, _ string) { cookies = append(cookies, n) }, func(_, _ string) {})
	if len(cookies) != 0 {
		t.Fatal("host filter failed")
	}

	inj.Remove("10.0.0.5")
	if _, ok := inj.Rule("10.0.0.5"); ok {
		t.Fatal("rule not removed")
	}
}

func TestInjectorRealRequest(t *testing.T) {
	inj := NewInjector()
	inj.Add(CookieInjection{VictimIP: "1.2.3.4", Host: "", Cookies: map[string]string{"token": "x"}})
	req, _ := http.NewRequest("GET", "http://anyhost/", nil)
	req.RemoteAddr = "1.2.3.4:9999"
	inj.Apply("1.2.3.4", req.Host, func(n, v string) { req.AddCookie(&http.Cookie{Name: n, Value: v}) }, func(k, v string) { req.Header.Set(k, v) })
	if got := req.Header.Get("Cookie"); got != "token=x" {
		t.Fatalf("cookie not set: %q", got)
	}
}
