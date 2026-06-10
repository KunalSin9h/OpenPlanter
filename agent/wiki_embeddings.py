"""Embeddings-backed semantic search over the runtime wiki.

Consumes the (otherwise unused) Voyage API key to index wiki entries and answer
``search_wiki`` queries. The index is chunked per (file, ## section), cached to
``.openplanter/wiki.embeddings.json`` keyed by a content hash, and rebuilt lazily
only when the wiki content or embedding model changes — so there is no network at
startup. All failures degrade to a plain string the agent can act on; nothing here
raises into the engine loop on the happy path.
"""
from __future__ import annotations

import hashlib
import json
import math
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

VOYAGE_URL = "https://api.voyageai.com/v1/embeddings"
_CACHE_NAME = "wiki.embeddings.json"
_SKIP_FILES = {"template.md"}


@dataclass
class _Chunk:
    rel_path: str
    section: str
    text: str


def _iter_chunks(wiki_dir: Path) -> list[_Chunk]:
    """Split every wiki .md into (file, ## section) chunks, titled for context."""
    chunks: list[_Chunk] = []
    for md in sorted(wiki_dir.rglob("*.md")):
        if md.name in _SKIP_FILES:
            continue
        rel = md.relative_to(wiki_dir).as_posix()
        try:
            raw = md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = raw.splitlines()
        title = next((ln[2:].strip() for ln in lines if ln.startswith("# ")), rel)
        current = "(intro)"
        buf: list[str] = []

        def flush() -> None:
            body = "\n".join(buf).strip()
            if body:
                chunks.append(_Chunk(rel, current, f"{title} — {current}\n{body}"))

        for ln in lines:
            if ln.startswith("## "):
                flush()
                current = ln[3:].strip()
                buf = []
            elif ln.startswith("# "):
                continue
            else:
                buf.append(ln)
        flush()
    return chunks


def _content_hash(chunks: list[_Chunk], model: str) -> str:
    h = hashlib.sha256()
    h.update(model.encode("utf-8"))
    for c in chunks:
        h.update(c.rel_path.encode("utf-8"))
        h.update(c.section.encode("utf-8"))
        h.update(c.text.encode("utf-8"))
    return h.hexdigest()


def _embed(texts: list[str], api_key: str, model: str, input_type: str, timeout: int = 30) -> list[list[float]]:
    """Call the Voyage embeddings API. Batches to stay under the 1000-input limit."""
    out: list[list[float]] = []
    for start in range(0, len(texts), 128):
        batch = texts[start:start + 128]
        payload = {"model": model, "input": batch, "input_type": input_type}
        req = urllib.request.Request(
            url=VOYAGE_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                parsed = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"Voyage HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise RuntimeError(f"Voyage network error: {exc}") from exc
        data = parsed.get("data") if isinstance(parsed, dict) else None
        if not isinstance(data, list):
            raise RuntimeError(f"Unexpected Voyage response: {str(parsed)[:200]}")
        for row in sorted(data, key=lambda r: r.get("index", 0)):
            out.append([float(x) for x in row.get("embedding", [])])
    return out


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


def _load_or_build_index(wiki_dir: Path, api_key: str, model: str) -> dict[str, Any]:
    """Return the cached index, rebuilding (and re-embedding) when stale."""
    chunks = _iter_chunks(wiki_dir)
    if not chunks:
        return {"hash": "", "model": model, "vectors": []}
    want_hash = _content_hash(chunks, model)
    cache_path = wiki_dir.parent / _CACHE_NAME
    if cache_path.is_file():
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            if cached.get("hash") == want_hash and cached.get("model") == model:
                return cached
        except (json.JSONDecodeError, OSError):
            pass
    # (Re)build the index.
    embeddings = _embed([c.text for c in chunks], api_key, model, input_type="document")
    vectors = [
        {"rel_path": c.rel_path, "section": c.section,
         "text": c.text, "embedding": emb}
        for c, emb in zip(chunks, embeddings)
    ]
    index = {"hash": want_hash, "model": model, "vectors": vectors}
    try:
        cache_path.write_text(json.dumps(index), encoding="utf-8")
    except OSError:
        pass  # search still works without a persisted cache
    return index


def search_wiki(
    wiki_dir: Path,
    query: str,
    top_k: int = 5,
    api_key: str | None = None,
    model: str = "voyage-3.5",
) -> str:
    """Semantic search over the wiki. Returns a JSON string of ranked results,
    or a plain fallback message when embeddings are unavailable."""
    fallback = (
        "search_wiki unavailable (no Voyage API key configured). Read "
        ".openplanter/wiki/index.md and use search_files/read_file over "
        ".openplanter/wiki/ instead."
    )
    if not (api_key and api_key.strip()):
        return fallback
    index = _load_or_build_index(wiki_dir, api_key.strip(), model)
    vectors = index.get("vectors", [])
    if not vectors:
        return "search_wiki: the wiki is empty — nothing to search."
    q_emb = _embed([query], api_key.strip(), model, input_type="query")[0]
    scored = [
        {
            "rel_path": v["rel_path"],
            "section": v["section"],
            "score": round(_cosine(q_emb, v["embedding"]), 4),
            "snippet": v["text"][:280],
        }
        for v in vectors
    ]
    scored.sort(key=lambda r: r["score"], reverse=True)
    result = {"query": query, "model": model, "results": scored[:max(1, min(top_k, 20))]}
    return json.dumps(result, indent=2, ensure_ascii=True)
