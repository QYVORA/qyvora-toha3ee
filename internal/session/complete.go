package session

import (
	"github.com/chzyer/readline"
)

// commandsCompleter builds the autocomplete tree for the REPL.
func commandsCompleter() []readline.PrefixCompleterInterface {
	base := []readline.PrefixCompleterInterface{
		readline.PcItem("help"),
		readline.PcItem("quit"),
		readline.PcItem("modules"),
		readline.PcItem("status"),
		readline.PcItem("set"),
		readline.PcItem("get"),
		readline.PcItem("config"),
		readline.PcItem("net.show"),
		readline.PcItem("events.show"),
		readline.PcItem("events.clear"),
		readline.PcItem("creds.show"),
		readline.PcItem("sessions.show"),
		readline.PcItem("session.hijack"),
		readline.PcItem("wizard"),
		readline.PcItem("report"),
		readline.PcItem("run.caplet"),
		readline.PcItem("on"),
		readline.PcItem("off"),
		readline.PcItem("clear"),
	}
	return base
}
