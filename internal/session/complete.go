package session

import (
	"github.com/chzyer/readline"

	"github.com/qyvora/toha3ee/internal/attacks"
)

// commandsCompleter builds the autocomplete tree for the REPL.
func commandsCompleter() []readline.PrefixCompleterInterface {
	var moduleItems []readline.PrefixCompleterInterface
	var catItems []readline.PrefixCompleterInterface
	var keyItems []readline.PrefixCompleterInterface
	seenCat := map[string]bool{}
	for _, m := range attacks.List() {
		meta := m.Meta()
		moduleItems = append(moduleItems, readline.PcItem(meta.ID))
		keyItems = append(keyItems, readline.PcItem(meta.ID+"."))
		if !seenCat[meta.Category] {
			seenCat[meta.Category] = true
			catItems = append(catItems, readline.PcItem(meta.Category))
		}
	}

	return []readline.PrefixCompleterInterface{
		readline.PcItem("help"),
		readline.PcItem("?"),
		readline.PcItem("quit"),
		readline.PcItem("exit"),
		readline.PcItem("bye"),
		readline.PcItem("modules", catItems...),
		readline.PcItem("list", catItems...),
		readline.PcItem("show", moduleItems...),
		readline.PcItem("module", append([]readline.PrefixCompleterInterface{readline.PcItem("on"), readline.PcItem("off"), readline.PcItem("start"), readline.PcItem("stop")}, moduleItems...)...),
		readline.PcItem("on", moduleItems...),
		readline.PcItem("off", moduleItems...),
		readline.PcItem("start", moduleItems...),
		readline.PcItem("stop", moduleItems...),
		readline.PcItem("status"),
		readline.PcItem("running"),
		readline.PcItem("set", keyItems...),
		readline.PcItem("get", keyItems...),
		readline.PcItem("config"),
		readline.PcItem("net.show"),
		readline.PcItem("hosts"),
		readline.PcItem("net.recon"),
		readline.PcItem("net.profile"),
		readline.PcItem("vectors.show"),
		readline.PcItem("vectors"),
		readline.PcItem("events.show"),
		readline.PcItem("events.clear"),
		readline.PcItem("creds.show"),
		readline.PcItem("creds"),
		readline.PcItem("sessions.show"),
		readline.PcItem("sessions"),
		readline.PcItem("session.hijack"),
		readline.PcItem("phish.list"),
		readline.PcItem("phish.serve"),
		readline.PcItem("hijack.dump"),
		readline.PcItem("wizard"),
		readline.PcItem("report"),
		readline.PcItem("sleep"),
		readline.PcItem("run.caplet"),
		readline.PcItem("script"),
		readline.PcItem("run.script"),
		readline.PcItem("build"),
		readline.PcItem("plan"),
		readline.PcItem("clear"),
	}
}
