# Security Policy

toha3ee is an **authorised-engagement network security tool**. It actively
poisons, redirects and intercepts network traffic. Its entire value proposition
is that it breaks the confidentiality, integrity and availability of network
communications — which makes a responsible disclosure policy essential.

## Supported versions

| Version | Supported          |
|---------|--------------------|
| latest release | :white_check_mark: |
| < latest release | :x: |

Security fixes are applied to the latest release only. Backports are made on a
best-effort basis for high-severity issues.

## Reporting a vulnerability

Please **do not open a public GitHub issue** for security problems. Instead,
email the maintainers and allow time for a coordinated fix:

- **Contact**: open a GitHub issue titled `security` with the label `security`
  disabled, or use GitHub's private vulnerability reporting (Security →
  *Report a vulnerability*) if enabled on the repository.
- **Response**: acknowledgement within **72 hours**, a fix plan within **7 days**.

If you use private reporting, include:

1. The affected module ID(s) and version.
2. A description of the vulnerability and its impact.
3. Steps to reproduce (or a minimal proof of concept) — **against a lab
   environment you own**.
4. Any suggested remediation.

## What is in scope

- Bugs in toha3ee itself that cause crashes, data loss, privilege escalation of
  the toha3ee process, or unsafe default behaviour.
- Module logic that breaks the documented `Cleanup()` contract and leaves a
  network in a poisoned or disrupted state.
- Config/script parsing that allows unexpected code or file-side effects.

## What is out of scope

- The inherent capabilities of the tool. By design toha3ee can disrupt,
  intercept and decrypt network traffic — that is its documented function.
  Do not report "toha3ee can ARP-spoof" as a vulnerability.
- Attacks that rely on **misuse against networks you do not own**. The tool
  ships prominent warnings; abuse of the tool is not a defect in the tool.
- Issues in third-party dependencies; report those upstream.

## Responsible-use reminder

toha3ee may only be used on networks you own or are explicitly authorised to
test. See [`docs/security.md`](docs/security.md) for the full responsible-use
policy. Evidence that a reporter is using the tool for unauthorised purposes
may be referred to the appropriate authorities and the report closed.

## Disclosure

Once a fix is released, the issue may be disclosed publicly (e.g. via
[`CHANGELOG.md`](CHANGELOG.md) and an advisory) with credit to the reporter
unless anonymity is requested.
