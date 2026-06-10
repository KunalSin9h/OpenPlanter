# npm Registry

## Summary

The public npm registry (registry.npmjs.org) serves all package metadata and tarballs for
the npm ecosystem. It is the primary source for triaging a suspect npm package: who
published it and when, every version, dependencies, dist-tags, and the download URL +
integrity hash for the tarball you'll statically analyze. Free, no auth for reads.

## Access Methods

- **Base URL**: `https://registry.npmjs.org/`
- **Downloads counts**: `https://api.npmjs.org/downloads/`
- **Auth**: none for public reads. **Rate limits**: not formally published; be polite.

## Data Schema

| Endpoint | Returns |
|----------|---------|
| `GET /{name}` | Full "packument": all versions, `time` (publish timestamps per version), `maintainers`, `dist-tags`, per-version `dist.tarball` + `dist.integrity`/`shasum`, `dependencies`, `scripts` (incl. pre/post-install hooks) |
| `GET /{name}/{version}` | Single version manifest (smaller) |
| `GET /-/v1/search?text={q}&size={n}&from={off}` | Search by text; paginated |
| `GET https://api.npmjs.org/downloads/point/{period}/{pkg}` | Download counts; period = last-day/last-week/last-month |

- Scoped packages: URL-encode the slash, e.g. `@scope/name` → `%40scope%2Fname`.
- **Tarball URL** pattern: `https://registry.npmjs.org/{name}/-/{name}-{version}.tgz`
  (for scoped, the unscoped name is used after `/-/`). Fetch + `tar -xzf` to inspect —
  never `npm install`.

## Coverage

- **Ecosystems**: npm only.
- **Scope**: every public npm package + version + tarball; unpublished/private excluded.
- **Update frequency**: real-time on publish.
- **Volume**: millions of packages; large packuments (many versions) can be tens of MB.

## Cross-Reference Potential

- **OSV.dev**: query each name+version for `MAL-`/advisory matches.
- **deps.dev**: resolved dependency graph, provenance, and advisory rollup.
- **OSSF Malicious Packages**: check whether this name already has a curated report.
- **GitHub Code Search**: pivot on the maintainer account, repo URL, or an IOC string
  found in `scripts`/tarball.
- **YARA-X**: scan the unpacked tarball with campaign rules.
- Join keys: package name + version, `dist.integrity` (sha512), maintainer email, publish
  timestamp (for clustering packages published in the same window).

## Data Quality

- `scripts` lifecycle hooks (preinstall/install/postinstall) are the highest-signal field
  for npm malware — read them first.
- Packuments for popular packages are huge; prefer `GET /{name}/{version}` when you know
  the version.
- Some metadata mirrors are stale; treat registry.npmjs.org as authoritative.

## Acquisition Script

```bash
curl -s https://registry.npmjs.org/<pkg> | jq '.time, .maintainers, .versions["<v>"].scripts'
# Download + unpack WITHOUT installing:
curl -sL https://registry.npmjs.org/<pkg>/-/<pkg>-<v>.tgz -o pkg.tgz && tar -xzf pkg.tgz
```
Prefer the `registry_metadata` and `download_package` tools.

## References

- https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md
- https://api-docs.npmjs.com/
