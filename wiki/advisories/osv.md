# OSV.dev

## Summary

OSV.dev is Google/OpenSSF's open vulnerability database and API. Critically for this work,
it ingests the OSSF malicious-packages dataset, so a single query tells you whether a
package+version is flagged as a known vulnerability OR known malware (`MAL-` IDs). It is
the first feed to hit when triaging a candidate, and the backbone for confirming clusters.
Free, no auth.

## Access Methods

- **Base URL**: `https://api.osv.dev/`
- `POST /v1/query` — one package/version or commit
- `POST /v1/querybatch` — many queries at once (returns IDs; faster, paginates at scale)
- `GET /v1/vulns/{id}` — full record for an ID (e.g. `MAL-2024-1234`, `GHSA-...`, `CVE-...`)
- **Auth**: none. **Limits**: generous; HTTP/2 recommended for large responses (32 MiB cap on HTTP/1.1).

## Data Schema

Query body:
```json
{"package": {"ecosystem": "npm", "name": "left-pad"}, "version": "1.0.0"}
```
(omit `version` to get all advisories for the package). Response `vulns[]` follows the
[OSV schema](https://ossf.github.io/osv-schema/): `id`, `modified`, `summary`, `details`,
`affected[]` (with `package`, `ranges`, `versions`), `references[]`, `aliases`, `credits`.

- **Malicious packages**: IDs prefixed `MAL-` come from the OSSF dataset; `affected[].database_specific`
  often carries the report source. Ecosystems include `npm`, `PyPI`, `Go`, `crates.io`, etc.
- `querybatch` returns only IDs+modified per query — follow up with `GET /v1/vulns/{id}`.

## Coverage

- **Ecosystems**: 30+ including npm and PyPI.
- **Scope**: vulnerabilities + malicious packages (via OSSF import).
- **Update frequency**: continuous import from upstream databases.

## Cross-Reference Potential

- **OSSF Malicious Packages**: `MAL-` records originate from this dataset; cross-check the source repo.
- **deps.dev**: deps.dev surfaces OSV advisories per package version.
- **OSV-Scanner**: the CLI that runs OSV queries over a whole project/lockfile.
- **npm Registry** / **PyPI JSON API**: get versions to query, then map advisory → affected versions.
- **Advisory Databases**: GHSA/CVE aliases resolve to the upstream advisory.
- Join keys: ecosystem + package name + version; advisory ID; CVE/GHSA aliases.

## Data Quality

- Not every malicious package is in OSV yet — absence is NOT proof of safety (record it as
  "no advisory found", a confidence signal, not a verdict).
- `MAL-` records may be terse; follow `references` to the original report.

## Acquisition Script

```bash
curl -s -X POST https://api.osv.dev/v1/query \
  -d '{"package":{"ecosystem":"npm","name":"<pkg>"}}' | jq '.vulns[].id'
```
Prefer the `osv_query` tool.

## References

- https://google.github.io/osv.dev/api/
- https://ossf.github.io/osv-schema/
- https://openssf.org/blog/2026/05/20/detecting-malicious-packages-using-the-osv-api/
