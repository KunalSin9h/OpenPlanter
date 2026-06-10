# VirusTotal

## Summary

VirusTotal aggregates multi-engine AV verdicts plus behavioral and relationship data for
files, URLs, domains, and IPs. For supply-chain work it's a fast reputation check on a
second-stage payload hash or a C2 domain extracted from a package, and the home of the YARA
ecosystem (VT authors YARA-X). **Optional — requires a free API key**; the public tier is
rate-limited (~4 req/min).

## Access Methods

- **Base URL**: `https://www.virustotal.com/api/v3/`
- `GET /files/{sha256}`, `GET /urls/{id}`, `GET /domains/{domain}`, `GET /ip_addresses/{ip}`
- **Auth**: `x-apikey: <key>` header (free account). **Limits**: public tier ~4/min, 500/day.
- Never *submit* a live sample you don't want disclosed; prefer hash lookups.

## Data Schema

`data.attributes`: `last_analysis_stats` (harmless/malicious/suspicious counts),
`last_analysis_results` per engine, `reputation`, `names`, `crowdsourced_yara_results`,
and relationship endpoints (`/files/{id}/contacted_domains`, `/behaviours`).

## Coverage

- **Scope**: files/URLs/domains/IPs generally — not package registries. Enrichment only.
- **Update frequency**: real-time on submission/rescan.

## Cross-Reference Potential

- **abuse.ch**: corroborate the same hash/domain across both feeds.
- **YARA-X**: VT hosts crowdsourced YARA matches and is the upstream of the YARA engine;
  rules transfer directly.
- Join keys: sha256/md5, domain, URL, IP.

## Data Quality

- Multi-engine verdicts are noisy; treat a single-engine hit as weak. Behavioral data is
  richer signal than the detection ratio.
- Free-tier rate limits are tight — cache results; tools must degrade gracefully without a key.

## Acquisition Script

```bash
curl -s https://www.virustotal.com/api/v3/files/<sha256> -H "x-apikey: $VT_API_KEY" \
  | jq '.data.attributes.last_analysis_stats'
```

## References

- https://docs.virustotal.com/reference/overview
