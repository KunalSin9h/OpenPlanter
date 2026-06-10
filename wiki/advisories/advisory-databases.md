# Advisory Databases

## Summary

The two upstream advisory corpora behind most ecosystem tooling: the **PyPA Advisory
Database** (Python) and the **GitHub Advisory Database / GHSA** (multi-ecosystem). Both are
OSV-formatted and consumable as git repos or via API. Use them to resolve CVE/GHSA aliases,
read the human-written advisory text, and confirm whether a finding is already disclosed.
Free.

## Access Methods

- **PyPA advisory-db**: `https://github.com/pypa/advisory-database` (clone; OSV JSON under `vulns/`).
- **GitHub Advisory DB**: browse at `https://github.com/advisories`; query via the GraphQL
  `securityAdvisories`/`securityVulnerabilities` API or REST `GET /advisories` (auth via
  `gh`/PAT). Also mirrored to OSV.dev.

## Data Schema

OSV-schema records: `id` (`GHSA-...`, `PYSEC-...`), `aliases` (CVE), `summary`, `details`,
`affected[]` (ecosystem, version ranges, fixed versions), `severity` (CVSS), `references`.

## Coverage

- **Ecosystems**: PyPA = PyPI; GHSA = npm, PyPI, and more.
- **Scope**: primarily known *vulnerabilities*; malicious-package coverage is lighter here
  than in **OSSF Malicious Packages** — use both.
- **Update frequency**: continuous.

## Cross-Reference Potential

- **OSV.dev**: both databases are imported into OSV; query OSV to hit them together.
- **PyPI JSON API**: the `vulnerabilities` array is sourced from PyPA advisory-db.
- **GitHub Code Search**: GHSA advisories link to fixing commits/repos to pivot from.
- Join keys: advisory ID, CVE alias, ecosystem + package + affected range.

## Data Quality

- Vulnerability-focused; a clean advisory result does NOT mean "not malware". Pair with
  **OSSF Malicious Packages** and **GuardDog**.

## Acquisition Script

```bash
git clone --depth 1 https://github.com/pypa/advisory-database
gh api graphql -f query='{ securityVulnerabilities(ecosystem: NPM, package:"<pkg>", first:5){nodes{advisory{ghsaId summary}}}}'
```

## References

- https://github.com/pypa/advisory-database
- https://github.com/advisories
- https://docs.github.com/en/rest/security-advisories
