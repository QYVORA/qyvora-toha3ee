# Reporting

`report.generate` renders a Markdown assessment report from everything the
session captured. The report is **only ever as good as the data in the store**
— run your recon and harvest modules first.

## Generating a report

```sh
# From the console
toha3eeλ> report engagement-1.md

# Via the report.generate module
toha3eeλ> on report.generate
# or with a custom path
toha3eeλ> set report.generate.out engagement-1.md
toha3eeλ> on report.generate

# From a .toha3ee script
report -> "engagement-1.md"
```

Default output path: `toha3ee-report.md`.

## Report structure

The generated Markdown contains four sections:

### 1. Header

```
# toha3ee assessment report
- Generated: <RFC3339 timestamp>
- Interface: <iface>
```

### 2. Hosts

One line per discovered host:

```
- **192.168.8.10** `aa:bb:cc:dd:ee:ff` (Vendor, Inc.) name="..." os="..." ports=[22,80,443]
```

For each host: IP, MAC + vendor, hostname, OS guess, and the list of open
ports captured so far.

### 3. Credentials

One line per captured credential, source-tracked:

```
- [http-basic] `admin`:`supersecret` host=192.168.8.10 victim=192.168.8.20 source=http.harvest at 2026-08-08T12:00:00Z
  - extra: `...`
```

Fields: service, username, password, host (credential target), victim IP,
capturing module (`source`), timestamp, optional extra data.

### 4. Sessions

One line per captured HTTP session:

```
- host=192.168.8.10 victim=192.168.8.20 cookies=`sessionid=abc123; csrf=xyz` at ...
```

### 5. Event log

The chronological framework event log, one line per event:

```
- `2026-08-08T12:00:01Z` [log] net.scan: 12 hosts discovered
```

## Interpreting the report

- **Hosts with no ports** — found on L2 but not yet service-scanned; run
  `service.synscan` / `service.tcpconnect`.
- **Credentials** are the highest-value output. Verify each with
  `session.replay` where applicable, then rotate them in the engagement
  report.
- **Missing sections** mean the corresponding data was never captured (empty
  store), not that it doesn't exist.

## Report lifecycle

| Module | Purpose |
|--------|---------|
| `report.generate` | write the Markdown assessment |
| `pcap.export` | copy the `http.harvest` capture to a stable path for evidence |
| `session.replay` | prove a captured session is still valid |

The exported pcap and the report together form the deliverable package for a
scoped engagement. Handle both as sensitive data (see
[Security & responsible use](security.md)).
