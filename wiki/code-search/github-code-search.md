# GitHub Code Search

## Summary

GitHub code search is the main way to hunt an IOC "in the wild" — a hardcoded C2 URL,
webhook, wallet, unusual string, or a distinctive install-hook pattern — across public
source. Finding the same indicator in other repos/packages is a strong pivot for expanding
a campaign. Two surfaces: the powerful web/UI+CLI search, and a much more limited REST API.

## Access Methods

- **CLI (preferred)**: `gh search code '<query>'` — reuses your `gh` auth, exposes the
  modern code-search engine and qualifiers. Also `gh api` for advisories/repos.
- **REST**: `GET /search/code?q=...` — requires auth; **~9 requests/min**; only the default
  branch; files **≤384 KB**; query must include ≥1 term and be ≤256 chars / ≤5 boolean ops.
  Send `Accept: application/vnd.github.text-match+json` for highlighted matches.
- **Web UI**: `https://github.com/search?type=code&q=...` — richest, but not scriptable.
- **Auth**: `GITHUB_TOKEN`/`GH_TOKEN` PAT or `gh auth login`.

## Data Schema

Qualifiers: `language:`, `path:`, `extension:`, `repo:`, `org:`, `user:`, `in:file|path`,
`size:`. REST response: `total_count`, `incomplete_results`, `items[]` with `repository`,
`path`, `html_url`, and `text_matches` when requested.

## Coverage

- **Scope**: public repositories' default branches. Not a package registry — use it to
  pivot from indicators to source, then back to **npm Registry**/**PyPI JSON API**.
- **Update frequency**: continuous indexing (with lag for new repos).

## Cross-Reference Potential

- **npm Registry** / **PyPI JSON API**: a matching repo often maps to a published package
  (check `package.json`/`setup.py`); pivot to registry metadata + tarball.
- **YARA-X**: turn a recurring code-search string into a YARA string and vice-versa.
- **abuse.ch**: cross-check any C2 domain/URL found in matched code.
- Join keys: IOC string, repo URL, maintainer/account handle.

## Data Quality

- REST code search is **rate-limited and weaker than the UI** — prefer `gh search code`.
- Obfuscated/minified payloads often won't match plaintext IOC searches; search on the
  decoded indicator (decoded base64, the literal URL) instead.
- 384 KB file cap means large bundles may be skipped.

## Acquisition Script

```bash
gh search code 'discord.com/api/webhooks' --limit 50 --json repository,path,textMatches
gh search code 'language:javascript "child_process" "postinstall"' --limit 30
```
Prefer the `github_code_search` tool.

## References

- https://docs.github.com/en/rest/search/search
- https://docs.github.com/en/search-github/searching-on-github/searching-code
