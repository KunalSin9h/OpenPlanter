"""Tests for the OSS supply-chain malware investigation tools and wiki embeddings.

Network-free: tool tests exercise argument validation and the safe-extraction
helpers; embeddings tests stub the Voyage call so ranking/cache/fallback logic is
deterministic.
"""
from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from agent import wiki_embeddings as we
from agent.tools import WorkspaceTools


class ToolArgValidationTests(unittest.TestCase):
    """Each tool rejects bad/missing args before any network call."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.t = WorkspaceTools(root=Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_osv_query_requires_name_and_ecosystem(self) -> None:
        self.assertIn("requires", self.t.osv_query("", "npm"))
        self.assertIn("requires", self.t.osv_query("pkg", ""))

    def test_registry_metadata_requires_name(self) -> None:
        self.assertIn("requires", self.t.registry_metadata("npm", ""))

    def test_registry_metadata_rejects_unknown_ecosystem(self) -> None:
        self.assertIn("unsupported", self.t.registry_metadata("rubygems", "x"))

    def test_download_package_requires_name(self) -> None:
        self.assertIn("requires", self.t.download_package("npm", ""))

    def test_github_code_search_requires_query(self) -> None:
        self.assertIn("requires", self.t.github_code_search(""))

    def test_yara_scan_requires_rules(self) -> None:
        self.assertIn("requires", self.t.yara_scan("", "."))

    def test_normalize_ecosystem(self) -> None:
        self.assertEqual(WorkspaceTools._normalize_ecosystem("node"), "npm")
        self.assertEqual(WorkspaceTools._normalize_ecosystem("pip"), "PyPI")


class SafeExtractTests(unittest.TestCase):
    """download_package extraction must stay in-workspace and non-executable."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.t = WorkspaceTools(root=Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _make_tar(self, members: dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, data in members.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    def test_extract_writes_non_executable_files(self) -> None:
        dest = Path(self.tmp.name) / "out"
        dest.mkdir()
        blob = self._make_tar({"package/index.js": b"console.log(1)"})
        n = self.t._safe_extract_tar(blob, dest)
        self.assertEqual(n, 1)
        f = dest / "package" / "index.js"
        self.assertTrue(f.is_file())
        self.assertEqual(f.stat().st_mode & 0o111, 0)  # no exec bits

    def test_path_traversal_member_is_skipped(self) -> None:
        dest = Path(self.tmp.name) / "out"
        dest.mkdir()
        blob = self._make_tar({"../escape.js": b"evil", "package/ok.js": b"ok"})
        self.t._safe_extract_tar(blob, dest)
        # The traversal member must NOT land outside dest.
        self.assertFalse((Path(self.tmp.name) / "escape.js").exists())
        self.assertTrue((dest / "package" / "ok.js").exists())


class WikiEmbeddingsTests(unittest.TestCase):
    VOCAB = ["yara", "rule", "osv", "malicious", "npm", "install", "hook", "search"]

    def _wiki(self) -> Path:
        root = Path(self.tmp.name)
        wiki = root / ".openplanter" / "wiki"
        wiki.mkdir(parents=True)
        (wiki / "index.md").write_text("# Index\n\n## Scanners\n\n| S | L |\n| - | - |\n| YARA-X | [y.md](scanners/y.md) |\n", encoding="utf-8")
        (wiki / "template.md").write_text("# Template\n\n## Summary\n\nskip me\n", encoding="utf-8")
        (wiki / "scanners").mkdir()
        (wiki / "scanners" / "y.md").write_text(
            "# YARA-X\n\n## Summary\n\nAuthor a yara rule and match malicious packages.\n"
            "\n## Coverage\n\nScans npm install hook payloads.\n", encoding="utf-8")
        return wiki

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self._orig_embed = we._embed

    def tearDown(self) -> None:
        we._embed = self._orig_embed
        self.tmp.cleanup()

    def _stub_embed(self):
        def fake(texts, api_key, model, input_type, timeout=30):
            return [[float(t.lower().count(w)) for w in self.VOCAB] for t in texts]
        return fake

    def test_template_skipped_and_chunks_built(self) -> None:
        wiki = self._wiki()
        chunks = we._iter_chunks(wiki)
        rels = {c.rel_path for c in chunks}
        self.assertIn("scanners/y.md", rels)
        self.assertNotIn("template.md", rels)  # template.md excluded

    def test_no_key_returns_fallback(self) -> None:
        wiki = self._wiki()
        out = we.search_wiki(wiki, "yara", api_key=None)
        self.assertIn("search_files", out)

    def test_ranking_and_cache(self) -> None:
        wiki = self._wiki()
        we._embed = self._stub_embed()
        out = json.loads(we.search_wiki(wiki, "yara rule malicious", top_k=2, api_key="k", model="m"))
        self.assertGreater(len(out["results"]), 0)
        # The y.md Summary mentions yara/rule/malicious — should rank first.
        self.assertEqual(out["results"][0]["rel_path"], "scanners/y.md")
        # Cache written and hash stable across loads.
        cache = wiki.parent / "wiki.embeddings.json"
        self.assertTrue(cache.is_file())
        h1 = we._load_or_build_index(wiki, "k", "m")["hash"]
        h2 = we._load_or_build_index(wiki, "k", "m")["hash"]
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_cosine(self) -> None:
        self.assertAlmostEqual(we._cosine([1, 0], [1, 0]), 1.0)
        self.assertAlmostEqual(we._cosine([1, 0], [0, 1]), 0.0)
        self.assertEqual(we._cosine([], [1]), 0.0)


if __name__ == "__main__":
    unittest.main()
