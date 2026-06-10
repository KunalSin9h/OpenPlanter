# [Source Name]

## Summary

One-paragraph overview: what this source provides, who runs it, and how it helps a
supply-chain malware investigation (triage, pivoting, attribution, or detection).

## Access Methods

How to query or obtain the data (REST API, bulk download, CLI, git clone). Include base
URLs, authentication requirements, and rate limits. Note whether an API key is needed and
whether the source is free.

## Data Schema

Key endpoints, request parameters, and the response fields that matter for investigation.
Include a field table if the schema is non-trivial.

## Coverage

- **Ecosystems**: npm, PyPI, etc.
- **Scope**: what's included vs. excluded
- **Update frequency**: how fresh the data is
- **Volume**: approximate counts if known

## Cross-Reference Potential

Which other sources in this wiki this one joins to, and on what key (package name +
ecosystem, version, hash, account/email, C2 domain, advisory ID). Reference the other
sources by their **exact bold name** as it appears in index.md so the knowledge graph
wires the edge.

## Data Quality

Known issues: stale/deprecated fields, coverage gaps, rate-limit pain, false
positives/negatives.

## Acquisition Script

Example queries or commands (curl, gh, the agent's first-class tools) to pull from this
source. Never execute downloaded package code as part of acquisition.

## References

Links to official docs, the API reference, and the data schema.
