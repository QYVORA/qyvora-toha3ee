# Scripting reference

`.toha3ee` files drive the full recon → attack → report pipeline with a
Python-like language. Execute one with `toha3ee script <file>`, from the REPL
with `script <file>` or `run <file>.toha3ee`, or validate it dry with
`toha3ee build <file>` / REPL `build <file>`. A working end-to-end example
lives at `scripts/full-pipeline.toha3ee`.

## A complete example

```toha3ee
# comment (or //)

set net.scan.targets -> "192.168.8.0/24"     # configure a module
on net.scan                                   # start a module
wait for net.scan                             # block until it finishes
_hosts -> [$(net.hosts)]                      # capture a list
echo -> "found $(_hosts.size) hosts"

if $(hosts.count) > 1                         # conditions
    on arp.spoof targets "192.168.8.0/24"
    sleep -> 30
    off arp.spoof
end

for each _h in $(_hosts)                      # loops
    repeat 3 times
        exec -> net.show                      # run any REPL command once
        break
    end
end

get net.scan.timeout -> _t                    # read a config value
report -> "assessment.md"                     # write the session report
```

## Statements

| Statement | Description |
|-----------|-------------|
| `set <module.key> -> <value>` | configure a module (also `=`) |
| `get <module.key> -> _var` | read a config value into a variable |
| `on <module> [key value ...]` | start a module (also `start`, `run`) |
| `off <module>` | stop a module (also `stop`) |
| `wait for <module> [max <secs>]` | block until the module finishes |
| `sleep <secs>` | pause |
| `echo -> "text"` | print (also `say`, `print`) |
| `show <module>` | print a module's metadata |
| `report <file>` | write the session report |
| `exec -> <command>` | run any REPL command once |
| `if <cond>` … `else` … `end` | conditionals |
| `for each _x in <list>` … `end` | loops |
| `repeat N times` … `end` | fixed-iteration loop |
| `while <cond>` … `end` | bounded loop (capped, cannot hang) |
| `break` / `continue` | loop control |
| `stop` | halt the script |

## Variables

- `_name -> value`, `_name = value` or `_name >> value` assigns a script
  variable.
- `[...]` builds a list from a property: `_hosts -> [$(net.hosts)]`.
- `$(_name.size)` and `$(_list.size)` return lengths.

## Strings and quoting

- Double-quoted `"..."` strings interpolate `$(...)` and honour the escapes
  `\n`, `\t`, `\r`, `\"`, `\\` and `\$`.
- Single-quoted `'...'` strings are **literal**: no escapes, and `$(...)` is
  kept as-is rather than resolved.
- Unquoted values (numbers, IPs, CIDRs, module option values, command flags)
  are taken verbatim, so `exec -> nmap -sS -p 80,443 10.0.0.1` and negative
  numbers like `_offset -> -1` both work.
- Module option values may mix quotes and comma-separated pieces, and
  interpolation survives: `on arp.spoof targets 10.0.0.1,$(_hosts)`.

## Interpolation

`$(...)` resolves live session state:

| Path | Value |
|------|-------|
| `$(hosts.count)` | number of discovered hosts |
| `$(net.hosts)` | list of discovered host IPs |
| `$(creds.count)` | number of captured credentials |
| `$(sessions.count)` | number of captured sessions |
| `$(running.list)` | modules currently running |
| `$(iface.ip)` / `$(iface.cidr)` | interface IP / CIDR |
| `$(iface.mac)` / `$(iface.gateway)` | interface MAC / gateway |
| `$(config.<module.key>)` | any configured value |
| `$(_myvar)` | a script variable |

## Conditions

- Operators: `==`, `!=`, `<`, `>`, `<=`, `>=`, `&&`, `||`, `!`.
- Numbers compare numerically; strings compare lexically.
- `while` loops are capped so a bad condition can never hang the script.
- `break` and `continue` work inside all three loop forms (`for each`,
  `repeat`, `while`).
- `wait for <module> max <secs>` requires a numeric timeout.

## Safety model

Every script statement drives the exact same module lifecycle and
preflight/risk gates as the REPL. **A script cannot do anything the console
cannot** — the risk model and the `Cleanup()` contract still apply, and the
safety manager tears everything down on panic, error or signal.

## Reference scripts

- `scripts/full-pipeline.toha3ee` — recon → service probing → OSINT →
  vectors → optional ARP MITM → loot → report.

## Next steps

- [User guide](User-Guide.md) — console command reference
- [Configuration](Configuration.md) — where module keys come from
