# OSSF Malicious Packages

## Summary

`github.com/ossf/malicious-packages` is the OpenSSF community dataset of confirmed
malicious open-source packages, stored as OSV-schema JSON files. It's the canonical
ground-truth corpus for known-bad packages — invaluable as a seed source (mine it for a
campaign's siblings) and as a confirmation that a candidate is already documented. Feeds
into OSV.dev. Free; clone or read raw files.

## Access Methods

- **Repo**: `https://github.com/ossf/malicious-packages` (clone or read raw via
  `raw.githubusercontent.com`).
- **Layout**: `osv/malicious/{ecosystem}/{package}/{MAL-YYYY-NNNN}.json`
  (e.g. `osv/malicious/npm/@scope/name/MAL-2024-1234.json`). Withdrawn reports under
  `osv/withdrawn/`.
- Also mirrored into OSV.dev, so live lookups can go through **OSV.dev** instead of cloning.

## Data Schema

Each file is an OSV record: `id` (`MAL-...`), `summary`, `details` (often the behavioral
write-up), `affected[].package` (ecosystem+name), `affected[].versions`, `credits`,
`database_specific` (source of the report, e.g. an automated scanner or a researcher).

## Coverage

- **Ecosystems**: npm, PyPI, Go, RubyGems, crates.io, NuGet (any OSV-supported).
- **Scope**: confirmed-malicious packages requiring incident response + TOS violation.
- **Update frequency**: continuous PRs + automated high-confidence imports.
- **Volume**: tens of thousands of records, npm and PyPI dominant.

## Cross-Reference Potential

- **OSV.dev**: the live API surface for these same `MAL-` records.
- **npm Registry** / **PyPI JSON API**: pull the named package's metadata + tarball to
  analyze and to find sibling versions/accounts.
- **GitHub Code Search**: pivot from a report's IOCs (URLs, strings) to other repos/packages.
- Join keys: ecosystem + package name + version; `MAL-` ID; IOCs in `details`.

## Data Quality

- Report `details` quality varies (automated vs. human). Always re-derive IOCs from the
  actual sample, don't trust the summary alone.
- Coverage lags fresh campaigns by hours-to-days; combine with **GuardDog** scanning of
  newly-published packages.

## Acquisition Script

```bash
git clone --depth 1 https://github.com/ossf/malicious-packages
jq -r '.id' malicious-packages/osv/malicious/npm/**/*.json
# Or live: query OSV.dev (osv_query tool) which mirrors this dataset.
```

## References

- https://github.com/ossf/malicious-packages
- https://ossf.github.io/osv-schema/
