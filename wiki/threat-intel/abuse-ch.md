# abuse.ch

## Summary

abuse.ch runs three open threat-intel platforms useful for enriching IOCs pulled from a
malicious package: **MalwareBazaar** (malware samples, queryable by hash/tag/YARA),
**URLhaus** (malware-distribution URLs), and **ThreatFox** (general IOCs: domains, IPs,
URLs, hashes). When a package's payload drops a second-stage binary or beacons to a domain,
these tell you if it's already known threat infrastructure. Free with a registered Auth-Key.

## Access Methods

- **MalwareBazaar**: `POST https://mb-api.abuse.ch/api/v1/`
- **URLhaus**: `https://urlhaus-api.abuse.ch/v2/`
- **ThreatFox**: `POST https://threatfox-api.abuse.ch/api/v1/`
- **Auth**: a free `Auth-Key` HTTP header is now required (register at auth.abuse.ch).
  Bulk CSV/JSON dumps are also published.

## Data Schema

- **MalwareBazaar** queries: `get_info` (by sha256/md5/sha1), `get_file` (download sample,
  zip pw `infected`), `get_taginfo`, `get_siginfo`, `get_yarainfo`, fuzzy-hash lookups
  (imphash/tlsh). Returns detections, signatures, first-seen, reporter, integrations.
- **ThreatFox** queries: `search_ioc`, `search_hash`, `get_iocs` (recent, `days` 1-7),
  `taginfo`, `malwareinfo`. IOCs older than ~6 months are expired from the live API.
- **URLhaus**: recent/active malicious URLs, payloads, host info; rule exports (Suricata/Snort).

## Coverage

- **Scope**: general malware + network IOCs — NOT package-specific. Use to enrich a
  second-stage hash or C2 indicator, not to find packages directly.
- **Update frequency**: continuous; dumps every few minutes.

## Cross-Reference Potential

- **VirusTotal**: corroborate a sample hash's reputation/detections.
- **YARA-X**: MalwareBazaar supports YARA queries and shares rules; reuse rules both ways.
- **GitHub Code Search**: pivot a C2 domain/URL found here back to source/packages.
- Join keys: sha256/md5/imphash, domain/URL, malware family tag.

## Data Quality

- Auth-Key required since a recent policy change; tools must degrade gracefully without it.
- Live API drops old IOCs (~6mo); use the historical CSV/JSON dumps for older campaigns.

## Acquisition Script

```bash
curl -s https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: $ABUSECH_KEY" \
  -d 'query=get_info&hash=<sha256>' | jq '.data[].signature'
```

## References

- https://bazaar.abuse.ch/api/
- https://urlhaus-api.abuse.ch/
- https://threatfox.abuse.ch/api/
