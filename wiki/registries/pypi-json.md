# PyPI JSON API

## Summary

PyPI's JSON API exposes project and release metadata for the Python ecosystem: maintainer
info, classifiers, every release's distribution files (sdist + wheels) with hashes and
upload times, and a `vulnerabilities` array sourced from the advisory database. It's the
primary source for triaging a suspect PyPI package and locating the sdist/wheel to unpack
and analyze statically. Free, no auth.

## Access Methods

- **Project**: `GET https://pypi.org/pypi/{project}/json`
- **Release**: `GET https://pypi.org/pypi/{project}/{version}/json`
- **Simple index** (PEP 503/691): `https://pypi.org/simple/{project}/` (HTML or JSON via
  `Accept: application/vnd.pypi.simple.v1+json`)
- **Auth**: none. **Rate limits**: not formally published.

## Data Schema

| Field | Notes |
|-------|-------|
| `info` | name, version, author, maintainer, `project_urls` (Homepage/Source), `requires_dist`, classifiers |
| `urls` (release) / `releases` (project) | per-file `url`, `filename`, `packagetype` (sdist/bdist_wheel), `digests` (md5/sha256/blake2b_256), `upload_time_iso_8601` |
| `vulnerabilities` | array: `id`, `aliases` (CVE/GHSA), `link` (OSV), `fixed_in`, `withdrawn` |

- Normalize names per PEP 503 (lowercase, runs of `._-` → single `-`) before joining.
- Distribution URLs live under `files.pythonhosted.org`; fetch + extract (`tar -xzf` for
  sdist, `unzip` for `.whl`) — never `pip install`.

## Coverage

- **Ecosystems**: PyPI only.
- **Scope**: all public projects/releases + their distribution files.
- **Update frequency**: real-time on upload; `vulnerabilities` reflects the advisory DB.
- **Deprecated**: top-level `downloads` (always -1), `has_sig` (always false). Use the
  Simple index over the project endpoint's `releases` for large projects.

## Cross-Reference Potential

- **OSV.dev**: the `vulnerabilities` links point at OSV; query OSV directly for `MAL-` ids.
- **Advisory Databases**: `vulnerabilities` is sourced from PyPA advisory-db.
- **deps.dev**: dependency graph + provenance for the project.
- **OSSF Malicious Packages**: check for an existing curated report.
- **GuardDog**: run heuristic rules against the unpacked sdist/wheel.
- Join keys: normalized project name + version, sha256 digest, `setup.py`/`pyproject`
  hooks, author email, upload timestamp.

## Data Quality

- `setup.py` / `pyproject.toml` build hooks and `__init__.py` import side effects are the
  highest-signal fields for PyPI malware — read them first, never execute them.
- Wheels can ship compiled artifacts; treat binaries as opaque and hash them.

## Acquisition Script

```bash
curl -s https://pypi.org/pypi/<project>/json | jq '.info.author, .urls[].url, .vulnerabilities'
curl -sL <sdist_url> -o s.tar.gz && tar -xzf s.tar.gz   # extract, do NOT install
```
Prefer the `registry_metadata` and `download_package` tools.

## References

- https://docs.pypi.org/api/json/
- https://docs.pypi.org/api/index-api/
