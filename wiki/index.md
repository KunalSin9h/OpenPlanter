# Data Sources Wiki

Reference documentation for every source OpenPlanter uses to hunt malicious open-source
packages. Each entry follows a [standardized template](template.md) so agents and
contributors can quickly understand access methods, schema, and cross-reference potential.
Focus ecosystems: **npm** and **PyPI**. All sources here are open/public.

## Sources by Category

## Registries

| Source | Ecosystem | Link |
|--------|-----------|------|
| npm Registry | npm | [npm-registry.md](registries/npm-registry.md) |
| PyPI JSON API | PyPI | [pypi-json.md](registries/pypi-json.md) |

## Advisories

| Source | Scope | Link |
|--------|-------|------|
| OSV.dev | Multi-ecosystem vulns + malware | [osv.md](advisories/osv.md) |
| OSSF Malicious Packages | Curated malicious-package dataset | [ossf-malicious-packages.md](advisories/ossf-malicious-packages.md) |
| deps.dev | Package metadata + advisories + provenance | [deps-dev.md](advisories/deps-dev.md) |
| Advisory Databases | PyPA advisory-db + GitHub Advisory DB | [advisory-databases.md](advisories/advisory-databases.md) |

## Code Search

| Source | Scope | Link |
|--------|-------|------|
| GitHub Code Search | Source-hosting IOC search | [github-code-search.md](code-search/github-code-search.md) |

## Threat Intel

| Source | Scope | Link |
|--------|-------|------|
| abuse.ch | Malware samples + IOC feeds | [abuse-ch.md](threat-intel/abuse-ch.md) |
| VirusTotal | File/URL/hash reputation | [virustotal.md](threat-intel/virustotal.md) |

## Scanners

| Source | Scope | Link |
|--------|-------|------|
| YARA-X | Rule authoring + matching | [yara-x.md](scanners/yara-x.md) |
| GuardDog | Heuristic package scanner | [guarddog.md](scanners/guarddog.md) |
| OSV-Scanner | SCA + lockfile scanning | [osv-scanner.md](scanners/osv-scanner.md) |

## Contributing

To add a new source, copy [template.md](template.md) into the appropriate category folder
and fill in each section. Link it from this index under the right `## Category` heading.
In the entry's "Cross-Reference Potential" section, reference other sources by their
**exact bold name** from this index so the knowledge graph wires the edge.
