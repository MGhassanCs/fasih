# Security

## Design

`fasih` is built to be safe by construction.

- **It never executes the code it scans.** Analysis is `ast.parse` + regex only.
  There is no `eval`, no `exec`, no import of target modules. A malicious file
  being scanned cannot run.
- **No network, no AI, no telemetry.** The tool makes no outbound connections
  and calls no model or API. It runs fully offline.
- **No credentials handled.** The `HARDCODED-SECRET` rule detects secrets but
  never stores, transmits, or prints their values (snippets are redacted).
- **Auto-fix is safe.** `--fix` only applies mechanical, meaning-preserving
  edits, writes atomically (temp file + `os.replace`), and re-parses the result
  first — it will not leave unparseable source on disk. It is opt-in.

## The `fasih serve` dashboard

The local dashboard is hardened for a developer workstation:

- **Loopback only** by default (`127.0.0.1`). Binding elsewhere prints a warning.
- **Per-run token.** `fasih serve` prints a URL carrying a one-time token; every
  request must present it (constant-time compared). No unauthenticated request —
  CSRF from a page you visit, or a direct remote client — can trigger a scan.
- **`Host`-header validation** — only `localhost` / `127.0.0.1` / `::1` are
  served, which blocks DNS-rebinding. Combined with the same-origin policy (no
  CORS headers are sent), a malicious web page cannot read results.
- **Cross-site rejection** — requests a browser marks `Sec-Fetch-Site:
  cross-site` / `same-site`, or with a non-loopback `Origin`, are refused.
- **Strict headers** on every response: `Content-Security-Policy` (`default-src
  'none'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
- **GET-only and read-only.** The dashboard runs the scanner and renders HTML;
  it has no endpoint that modifies files. All rendered values are HTML-escaped.

Note: the dashboard will scan any path you ask it to and show source-line
snippets, so run it on machines and code you trust. It is a local dev tool, not
a multi-tenant service — do not expose it to untrusted networks.

## Reporting a vulnerability

Open a private security advisory on GitHub, or email the maintainer. Please do
not open a public issue for a security report.
