// Package capabilities exposes the machine-readable tool contract so
// automation and humans can read what this framework actually implements,
// without trusting prose.
package capabilities

import (
	"encoding/json"
	"fmt"
	"html"
	"sort"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/version"
)

// Capability lists one implemented capability area.
type Capability struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Implemented bool   `json:"implemented"`
	Risk        string `json:"risk,omitempty"`
	Passive     bool   `json:"passive"`
	Note        string `json:"note,omitempty"`
}

// Command describes one CLI command surface.
type Command struct {
	Name        string   `json:"name"`
	Summary     string   `json:"summary"`
	OutputModes []string `json:"output_modes"`
}

// Document is the full machine-readable contract of this framework build.
type Document struct {
	Framework      string       `json:"framework"`
	Version        string       `json:"version"`
	ExitCodes      map[string]int `json:"exit_codes"`
	OutputFormats  []string     `json:"output_formats"`
	EventVerbs     []string     `json:"event_verbs"`
	SeverityLevels []string     `json:"severity_levels"`
	RiskLevels     []string     `json:"risk_levels"`
	Authorized     string       `json:"authorization_model"`
	Capabilities   []Capability `json:"capabilities"`
	Commands       []Command    `json:"commands"`
	ModuleCount    int          `json:"module_count"`
	CategoryCount  int          `json:"category_count"`
}

// Build assembles the capability document for this build.
func Build() Document {
	modules := attacks.List()
	categories := attacks.Categories()
	
	caps := make([]Capability, 0, len(modules))
	for _, m := range modules {
		meta := m.Meta()
		caps = append(caps, Capability{
			ID:          meta.ID,
			Name:        meta.Description,
			Category:    meta.Category,
			Implemented: true,
			Risk:        meta.Risk.String(),
			Passive:     meta.Passive,
		})
	}

	return Document{
		Framework: version.Framework,
		Version:   version.Version,
		ExitCodes: map[string]int{
			"success": 0, "runtime": 1, "usage": 2, "interrupted": 130,
		},
		OutputFormats: []string{"terminal", "json", "markdown", "yaml", "html"},
		EventVerbs: []string{
			events.RunStarted, events.RunCompleted,
			events.ModuleStarted, events.ModuleStopped,
			events.ModuleFailed, events.ModuleCompleted,
			events.HostDiscovered, events.CredentialFound,
			events.SessionCaptured, events.ReportGenerated,
			events.Warning, events.Error,
		},
		SeverityLevels: []string{
			"critical", "high", "medium", "low", "info",
		},
		RiskLevels: []string{
			"info", "low", "medium", "high", "critical",
		},
		Authorized: "all active attack modules require explicit authorization " +
			"via --authorized flag or AUTHORIZED=yes in caplet; passive reconnaissance " +
			"modules do not require authorization",
		Capabilities:  caps,
		Commands: []Command{
			{Name: "tui", Summary: "launch interactive terminal interface", OutputModes: []string{"terminal"}},
			{Name: "wizard", Summary: "launch guided setup wizard", OutputModes: []string{"terminal"}},
			{Name: "eval", Summary: "evaluate commands non-interactively", OutputModes: []string{"terminal", "json", "markdown", "yaml", "html"}},
			{Name: "run", Summary: "execute a script or caplet", OutputModes: []string{"terminal", "json", "markdown", "yaml", "html"}},
			{Name: "script", Summary: "execute a .toha3ee script", OutputModes: []string{"terminal", "json", "markdown", "yaml", "html"}},
			{Name: "build", Summary: "validate script and print dry-run plan", OutputModes: []string{"terminal", "json", "markdown", "yaml", "html"}},
			{Name: "modules", Summary: "list all registered modules", OutputModes: []string{"terminal", "json", "markdown"}},
			{Name: "capabilities", Summary: "print this machine-readable contract", OutputModes: []string{"terminal", "json", "markdown", "yaml", "html"}},
			{Name: "version", Summary: "print version information", OutputModes: []string{"terminal", "json", "markdown"}},
			{Name: "report", Summary: "generate assessment report", OutputModes: []string{"terminal", "json", "markdown", "yaml", "html"}},
		},
		ModuleCount:   len(modules),
		CategoryCount: len(categories),
	}
}

// RenderJSON returns the document as JSON.
func RenderJSON() ([]byte, error) {
	doc := Build()
	SortCapabilities(&doc)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding capabilities: %w", err)
	}
	return data, nil
}

// RenderTable returns capability rows for terminal table rendering.
// Groups modules by category for better readability.
func RenderTable() map[string][][]string {
	doc := Build()
	
	// Group by category
	byCategory := make(map[string][]Capability)
	for _, c := range doc.Capabilities {
		byCategory[c.Category] = append(byCategory[c.Category], c)
	}
	
	// Convert to table rows per category
	result := make(map[string][][]string)
	for cat, caps := range byCategory {
		rows := make([][]string, 0, len(caps))
		for _, c := range caps {
			passive := "no"
			if c.Passive {
				passive = "yes"
			}
			rows = append(rows, []string{c.ID, c.Name, c.Risk, passive})
		}
		result[cat] = rows
	}
	
	return result
}

// SortCapabilities orders capabilities by category then ID for deterministic output.
func SortCapabilities(doc *Document) {
	sort.Slice(doc.Capabilities, func(i, j int) bool {
		if doc.Capabilities[i].Category != doc.Capabilities[j].Category {
			return doc.Capabilities[i].Category < doc.Capabilities[j].Category
		}
		return doc.Capabilities[i].ID < doc.Capabilities[j].ID
	})
}

// RenderYAML returns the document as YAML format.
func RenderYAML() ([]byte, error) {
	// Similar approach to session report: marshal to JSON then convert to YAML-like format
	doc := Build()
	SortCapabilities(&doc)
	
	jsonData, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal to JSON: %w", err)
	}
	
	// Simple YAML conversion (note: full YAML support would require gopkg.in/yaml.v3)
	result := fmt.Sprintf("# TOHA3EE Capabilities (YAML format)\n# Note: Full YAML support requires gopkg.in/yaml.v3 dependency\n\n")
	result += string(jsonData) // For now, just formatted JSON with YAML header
	
	return []byte(result), nil
}

// RenderHTML returns the document as HTML.
func RenderHTML() string {
	doc := Build()
	SortCapabilities(&doc)
	
	var html string
	html += "<!DOCTYPE html>\n<html>\n<head>\n"
	html += "<meta charset=\"UTF-8\">\n"
	html += "<title>TOHA3EE Capabilities</title>\n"
	html += "<style>\n"
	html += "body { font-family: sans-serif; max-width: 1200px; margin: 40px auto; padding: 0 20px; }\n"
	html += "h1 { color: #c41e3a; }\n"
	html += "h2 { color: #333; border-bottom: 2px solid #c41e3a; padding-bottom: 5px; margin-top: 30px; }\n"
	html += "table { border-collapse: collapse; width: 100%; margin: 20px 0; }\n"
	html += "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n"
	html += "th { background-color: #f2f2f2; font-weight: bold; }\n"
	html += "tr:nth-child(even) { background-color: #f9f9f9; }\n"
	html += ".meta { color: #666; margin: 20px 0; }\n"
	html += ".badge { padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }\n"
	html += ".badge-info { background: #d1ecf1; color: #0c5460; }\n"
	html += ".badge-low { background: #d4edda; color: #155724; }\n"
	html += ".badge-medium { background: #fff3cd; color: #856404; }\n"
	html += ".badge-high { background: #f8d7da; color: #721c24; }\n"
	html += ".badge-critical { background: #f5c6cb; color: #721c24; font-weight: bold; }\n"
	html += "</style>\n"
	html += "</head>\n<body>\n"
	html += "<h1>TOHA3EE Framework Capabilities</h1>\n"
	html += fmt.Sprintf("<div class=\"meta\"><strong>Framework:</strong> %s</div>\n", htmlEscape(doc.Framework))
	html += fmt.Sprintf("<div class=\"meta\"><strong>Version:</strong> %s</div>\n", htmlEscape(doc.Version))
	html += fmt.Sprintf("<div class=\"meta\"><strong>Modules:</strong> %d across %d categories</div>\n", doc.ModuleCount, doc.CategoryCount)
	
	// Group by category
	byCategory := make(map[string][]Capability)
	for _, c := range doc.Capabilities {
		byCategory[c.Category] = append(byCategory[c.Category], c)
	}
	
	// Get sorted categories
	categories := make([]string, 0, len(byCategory))
	for cat := range byCategory {
		categories = append(categories, cat)
	}
	sort.Strings(categories)
	
	// Render each category
	for _, cat := range categories {
		caps := byCategory[cat]
		html += fmt.Sprintf("\n<h2>%s (%d modules)</h2>\n", htmlEscape(cat), len(caps))
		html += "<table>\n<tr><th>ID</th><th>Description</th><th>Risk Level</th><th>Passive</th></tr>\n"
		for _, c := range caps {
			passive := "No"
			if c.Passive {
				passive = "Yes"
			}
			riskClass := "badge-" + c.Risk
			html += fmt.Sprintf("<tr><td><code>%s</code></td><td>%s</td><td><span class=\"badge %s\">%s</span></td><td>%s</td></tr>\n",
				htmlEscape(c.ID), htmlEscape(c.Name), riskClass, htmlEscape(c.Risk), passive)
		}
		html += "</table>\n"
	}
	
	html += "</body>\n</html>\n"
	return html
}

func htmlEscape(s string) string {
	return html.EscapeString(s)
}
