# Changelog

All notable changes to `fasih` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.3.1]

### Added
- **Folder browser** in the dashboard — navigate from your Desktop/home with
  breadcrumbs and click "Scan this folder" instead of typing paths. Flags which
  folders contain `.py`.

### Fixed
- Dashboard now expands `~` and environment variables in paths (a pasted
  `~/Desktop/project` no longer reports "no .py files"), and distinguishes
  "path not found" from "folder has no .py files (fasih is Python-only)".
- The scanner suppresses `SyntaxWarning`/`DeprecationWarning` while parsing
  third-party files it merely analyzes.

## [0.3.0]

### Added
- **Auto-fix** — `fasih scan --fix` applies mechanical fixes in place, and
  `--diff` previews them. Byte-precise, atomic, and re-parsed before writing.
  Fixable rules: `AR-ENCODING`, `AR-FILE-ENCODING`, `AR-ENCODE-ASCII`.
- **`AR-BIDI`** rule — flags string literals mixing Arabic with Latin/numbers
  without bidi isolation; ships `wrap_ltr()` / `isolate()`.
- **`fasih serve`** — a local, security-hardened web dashboard (stdlib only)
  that runs the scanner, explains every rule, and flags auto-fixable findings.
- **Configuration** via `pyproject.toml [tool.fasih]` or `.fasih.toml`
  (`arabic`, `fail_on`, `disable`, `ignore`); `--no-config` to opt out.
- **Pre-commit hook** (`.pre-commit-hooks.yaml`).
- `fasih scan` now accepts multiple paths.
- `SECURITY.md`, `CONTRIBUTING.md`, this changelog.

### Security
- Dashboard: loopback-only, `Host`-header validation (DNS-rebinding defense),
  strict CSP / `X-Frame-Options` / `nosniff` headers, GET-only, HTML-escaped.

## [0.2.0]

### Added
- Arabic module became the focus: **`AR-NORMALIZE`** (matching Arabic without
  normalizing alef/ya/ta-marbuta/tatweel/diacritics), **`AR-FILE-ENCODING`**,
  **`AR-ENCODE-ASCII`**.
- Normalization toolkit: `normalize_arabic()`, `strip_tashkeel()`,
  `strip_tatweel()`.

### Fixed
- `AR-NUMERAL` rationale corrected: Python's `int()`/`float()` accept
  Arabic-Indic digits; the real failures are the Arabic decimal/thousands
  separators and silent ASCII-only downstream handling.

## [0.1.0]

### Added
- Initial release. Core reliability rules (`FAIL-OPEN-GUARD`, `ORPHANED-TOOL`,
  `STRUCTURE-NOT-SEMANTICS`, `HARDCODED-SECRET`), the first Arabic rules
  (`AR-ENCODING`, `AR-NUMERAL`), `normalize_arabic_indic_digits()`, CLI, CI.
