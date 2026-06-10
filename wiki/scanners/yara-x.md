# YARA-X

## Summary

YARA-X is the Rust rewrite of YARA and the recommended engine going forward. In this
workflow it's the detection backbone: you author rules from indicators found in one
malicious package (strings, byte patterns, structural traits of the install hook) and match
them across other unpacked packages to find siblings. Rules double as portable, shareable
campaign signatures. Free, open source.

## Access Methods

- **Python**: `pip install yara-x`; `import yara_x`.
- **CLI**: the `yara-x` binary — `yara-x scan rules.yar <path>` (recurses directories).
- The legacy `yara`/`yara-python` still works but YARA-X is preferred (stricter regex; use
  `relaxed_re_syntax=True` in the compiler if porting old rules).

## Data Schema (rule structure)

```yara
rule npm_exfil_webhook {
  meta:
    campaign = "example-2026"
  strings:
    $a = "discord.com/api/webhooks"
    $b = /child_process.*exec\(/
    $c = { 68 74 74 70 73 3a }   // hex pattern
  condition:
    2 of ($a, $b, $c)
}
```
Python:
```python
import yara_x
rules = yara_x.compile(open("rules.yar").read())
for m in rules.scan(open("suspect.js","rb").read()).matching_rules:
    print(m.identifier)
```

## Coverage

- **Scope**: matches arbitrary files — here, the **unpacked** package trees from the
  registries. Engine only; brings no data of its own.

## Cross-Reference Potential

- **npm Registry** / **PyPI JSON API**: scan the tarballs/sdists you download from these.
- **abuse.ch** / **VirusTotal**: both host YARA rule sharing/matching; rules are portable
  in both directions.
- **GuardDog**: complementary — GuardDog brings curated heuristics, YARA-X brings your
  campaign-specific signatures.
- Join keys: rule hits across multiple packages = a candidate cluster edge.

## Data Quality

- Author tight rules: overly-broad strings (`require`, `eval`) cause false positives across
  benign packages. Require `N of` multiple distinctive indicators.
- Scan the extracted source, never run it.

## Acquisition Script

```bash
yara-x scan campaign.yar samples/        # scan all unpacked samples
```
Prefer the `yara_scan` tool (inline rules or a rules file against a workspace path).

## References

- https://virustotal.github.io/yara-x/
- https://virustotal.github.io/yara-x/docs/api/python/
