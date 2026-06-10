# OSV-Scanner

## Summary

OSV-Scanner is the official OSV.dev CLI: point it at a project, lockfile, SBOM, or
directory and it resolves dependencies and reports matching OSV advisories — including
`MAL-` malicious-package records. For investigation it's the fast way to check a whole
dependency tree (e.g. a victim project, or a downloaded package's deps) against OSV in one
pass. Built on OSV-Scalibr for extraction/SBOM. Free, no auth.

## Access Methods

- **Install**: prebuilt binaries / `go install github.com/google/osv-scanner/...`
- **Scan**: `osv-scanner scan -r <dir>` (recursive), `--lockfile <file>`, `--sbom <file>`
- **Output**: table (default), `--format json`, HTML report.
- **OSV-Scalibr**: the underlying library for package extraction + SBOM (SPDX/CycloneDX);
  usable standalone for deeper file-system scans.

## Data Schema

JSON output: `results[].packages[]` with `package` (name/version/ecosystem) and
`vulnerabilities[]` (OSV records, IDs incl. `MAL-`, `CVE`, `GHSA`), plus `groups`/severity.

## Coverage

- **Ecosystems**: all OSV-supported, including npm + PyPI lockfiles
  (`package-lock.json`, `pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`, etc.).
- **Update frequency**: queries live OSV.dev.

## Cross-Reference Potential

- **OSV.dev**: OSV-Scanner is just a batch front-end to the same database/API.
- **deps.dev**: both resolve dependency graphs; cross-check resolved versions.
- Join keys: ecosystem + package + version; advisory ID.

## Data Quality

- Findings are only as complete as OSV — a clean scan is not proof of safety for an
  unindexed fresh package; pair with **GuardDog** + manual review.

## Acquisition Script

```bash
osv-scanner scan -r ./samples/ --format json > osv_scan.json
osv-scanner --lockfile package-lock.json --format json
```
Run via the `run_shell` tool.

## References

- https://google.github.io/osv-scanner/
- https://github.com/google/osv-scalibr
