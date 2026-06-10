# deps.dev

## Summary

deps.dev (Google's Open Source Insights) provides a normalized cross-ecosystem view of a
package: versions, resolved dependency graph, licenses, OSV advisories, and — where
available — SLSA provenance and the source repo link. Useful for understanding a suspect
package's transitive blast radius and for pivoting to its upstream repository and publish
provenance. Free, no auth.

## Access Methods

- **Base URL**: `https://api.deps.dev/v3/`
- `GET /v3/systems/{system}/packages/{name}` — versions + default version
- `GET /v3/systems/{system}/packages/{name}/versions/{version}` — licenses, advisories,
  dependencies, related projects/provenance
- **systems**: `NPM`, `PYPI`, `GO`, `CARGO`, `MAVEN`, `NUGET`, `RUBYGEMS`
- **Auth**: none. Path params must be URL-encoded (`@`→`%40`, `/`→`%2F`).

## Data Schema

Version response includes `licenses`, `advisoryKeys` (→ OSV IDs), `links` (source repo,
issue tracker), `slsaProvenance` / `attestations` where published, and the dependency
graph via the dependencies endpoint. gRPC and a BigQuery dataset also exist for bulk work.

## Coverage

- **Ecosystems**: npm, PyPI, and 5 others.
- **Scope**: published packages; metadata + resolved deps + advisory rollup.
- **Update frequency**: regular crawl; not real-time on publish.

## Cross-Reference Potential

- **OSV.dev**: `advisoryKeys` map directly to OSV advisory IDs.
- **npm Registry** / **PyPI JSON API**: authoritative publish data; deps.dev normalizes + adds graph.
- **GitHub Code Search**: the `links` source repo is the pivot point for code search.
- Join keys: system + package name + version; advisory key; source repo URL.

## Data Quality

- Crawl lag means a brand-new malicious version may not appear yet — use the registries
  for freshness.
- Provenance/attestation coverage is partial; absence isn't suspicious by itself.

## Acquisition Script

```bash
curl -s 'https://api.deps.dev/v3/systems/NPM/packages/%40scope%2Fname/versions/1.2.3' | jq '.advisoryKeys, .links'
```
Prefer the `depsdev_lookup` tool.

## References

- https://docs.deps.dev/api/v3/
