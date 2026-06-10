# GuardDog

## Summary

GuardDog (DataDog, open source) is a CLI that flags likely-malicious PyPI/npm (and Go,
RubyGems, GitHub Actions, VS Code extension) packages using Semgrep source rules + metadata
heuristics. Because it detects attacker *patterns* (suspicious install hooks, obfuscation,
exfil, typosquatting signals) rather than signatures, it catches novel malware — ideal for
triaging freshly-published candidates the advisory feeds haven't caught yet. Free.

## Access Methods

- **Install**: `pip install guarddog` (or the official Docker image).
- **Scan remote**: `guarddog pypi scan <package>` / `guarddog npm scan <package>`
- **Scan local**: `guarddog pypi verify <path>` / point it at a downloaded archive/dir.
- Selectively include/exclude individual heuristics/rules.

## Data Schema

Output lists triggered heuristic IDs (e.g. `npm-install-script`, `code-execution`,
`obfuscation`, `exfiltrate-sensitive-data`, `potentially-compromised-email-domain`,
`typosquatting`) with the matching file/line. JSON output available for parsing.

## Coverage

- **Ecosystems**: PyPI + npm (primary), plus Go, RubyGems, GitHub Actions, VS Code.
- **Scope**: heuristic detection of malicious indicators in source + metadata.
- **Update frequency**: rules updated with releases.

## Cross-Reference Potential

- **npm Registry** / **PyPI JSON API**: scan packages pulled from these; corroborate the
  hooks GuardDog flags by reading the same files.
- **YARA-X**: turn a GuardDog finding into a reusable campaign YARA rule.
- **OSV.dev**: confirm whether a GuardDog hit is already a known `MAL-` advisory.
- Join keys: package name + version; shared heuristic hits across packages.

## Data Quality

- Heuristics produce false positives (legit packages use install scripts) — treat hits as
  leads to verify by reading the code, not verdicts.
- **Security note (CVE-2026-44972)**: GuardDog's human-readable output can include
  attacker-controlled filenames/code with unescaped terminal control characters → terminal
  injection risk. Prefer **JSON output** and avoid rendering raw output in a live terminal.

## Acquisition Script

```bash
guarddog pypi scan <package> --output-format json
guarddog npm verify ./samples/npm/<name>@<version>   # scan an already-unpacked dir
```
Run GuardDog via the `run_shell` tool; it does static analysis (no package execution).

## References

- https://github.com/DataDog/guarddog
