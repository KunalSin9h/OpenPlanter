"""Wiki knowledge graph model.

Parses the wiki directory, extracts cross-reference relationships between data
sources, and maintains a NetworkX graph that can be rendered as a character-cell
visualization in the Textual TUI.
"""
from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import networkx as nx
except ImportError:  # pragma: no cover
    nx = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Category → color mapping (ANSI color names used by Textual rich text)
# ---------------------------------------------------------------------------

CATEGORY_COLORS: dict[str, str] = {
    "registries": "green",
    "advisories": "yellow",
    "code-search": "cyan",
    "threat-intel": "bright_red",
    "scanners": "bright_magenta",
}

DEFAULT_NODE_COLOR = "white"

# ---------------------------------------------------------------------------
# Index parsing
# ---------------------------------------------------------------------------

# Matches a markdown link anywhere in a cell: [text](path)
_LINK_RE = re.compile(r"\[(?P<text>[^\]]+)\]\((?P<path>[^)]+)\)")

# Category labels: any heading level >= 2 (## .. ######).  Tolerant of whatever
# heading depth the model chooses; the H1 document title is ignored.
_CATEGORY_RE = re.compile(r"^#{2,}\s+(.+)$")

# A markdown table separator cell, e.g. ---, :--, --:, :--:
_SEPARATOR_CELL_RE = re.compile(r"^:?-+:?$")


@dataclass
class WikiEntry:
    """A single data source entry in the wiki."""

    name: str
    category: str  # e.g. "campaign-finance"
    rel_path: str  # relative path from wiki root, e.g. "campaign-finance/fec-federal.md"
    title: str = ""  # extracted from # heading in the file
    cross_refs: list[str] = field(default_factory=list)  # raw bold text from cross-ref section


def _category_slug(display_name: str) -> str:
    """Convert a display category name to a slug: 'Campaign Finance' -> 'campaign-finance'."""
    return display_name.strip().lower().replace(" & ", "-").replace(" ", "-")


def parse_index(wiki_dir: Path) -> list[WikiEntry]:
    """Parse wiki/index.md and return entries with name, category, path.

    Tolerant of layout: category labels may use any heading level (``##``+),
    and the entry link may appear in any table column.  The entry name is taken
    from the first non-link, non-empty cell (falling back to the link text).
    This accepts both the canonical baseline layout
    (``| Name | Jurisdiction | [link](path) |``) and looser tables the model
    may produce (e.g. the link in the second column).
    """
    index_path = wiki_dir / "index.md"
    if not index_path.is_file():
        return []

    entries: list[WikiEntry] = []
    current_category = ""
    for raw in index_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        cat_m = _CATEGORY_RE.match(line)
        if cat_m:
            current_category = _category_slug(cat_m.group(1))
            continue
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        # Skip table separator rows, e.g. | --- | --- |
        if cells and all(_SEPARATOR_CELL_RE.match(c) for c in cells if c):
            continue
        # Locate the first cell linking to a .md entry file.
        link_m = None
        link_idx = -1
        for i, cell in enumerate(cells):
            m = _LINK_RE.search(cell)
            if m and m.group("path").strip().endswith(".md"):
                link_m = m
                link_idx = i
                break
        if link_m is None:
            continue
        # Name = first non-link, non-empty cell; fall back to the link text.
        name = ""
        for i, cell in enumerate(cells):
            if i == link_idx or not cell:
                continue
            if not _LINK_RE.search(cell):
                name = cell
                break
        if not name:
            name = link_m.group("text").strip()
        entries.append(
            WikiEntry(
                name=name,
                category=current_category,
                rel_path=link_m.group("path").strip(),
            )
        )
    return entries


# ---------------------------------------------------------------------------
# Cross-reference extraction
# ---------------------------------------------------------------------------

# Matches bold references in cross-ref sections: **Something Here**
_BOLD_REF_RE = re.compile(r"\*\*([^*]+)\*\*")


def extract_cross_refs(file_path: Path) -> tuple[str, list[str]]:
    """Extract the title and cross-reference mentions from a wiki entry file.

    Returns (title, list_of_bold_references_in_cross_ref_section).
    """
    if not file_path.is_file():
        return "", []

    text = file_path.read_text(encoding="utf-8")
    lines = text.splitlines()

    # Extract title from first # heading
    title = ""
    for line in lines:
        if line.startswith("# ") and not line.startswith("##"):
            title = line[2:].strip()
            break

    # Find ## Cross-Reference Potential section
    in_section = False
    section_lines: list[str] = []
    for line in lines:
        if line.startswith("## Cross-Reference Potential"):
            in_section = True
            continue
        if in_section:
            if line.startswith("## "):
                break
            section_lines.append(line)

    # Extract bold references from bullet points
    refs: list[str] = []
    for line in section_lines:
        stripped = line.strip()
        if not stripped.startswith("-") and not stripped.startswith("*"):
            continue
        for m in _BOLD_REF_RE.finditer(stripped):
            ref_text = m.group(1).strip()
            # Skip generic labels like "Join keys" or "Critical note"
            lower = ref_text.lower()
            if lower.startswith("join") or lower.startswith("critical") or lower.startswith("geographic"):
                continue
            refs.append(ref_text)

    return title, refs


# ---------------------------------------------------------------------------
# Name registry and fuzzy matching
# ---------------------------------------------------------------------------

def _build_name_registry(entries: list[WikiEntry]) -> dict[str, str]:
    """Build a map from lowered name variants to canonical entry name.

    Registers: full name, parenthetical contents, acronyms, and key tokens.
    """
    registry: dict[str, str] = {}
    for entry in entries:
        canonical = entry.name
        # Full name
        registry[canonical.lower()] = canonical
        # Title from file (if different)
        if entry.title and entry.title.lower() != canonical.lower():
            registry[entry.title.lower()] = canonical

        # Extract parenthetical aliases: "Senate Lobbying Disclosures (LD-1/LD-2)" -> "LD-1/LD-2"
        paren_m = re.search(r"\(([^)]+)\)", canonical)
        if paren_m:
            inner = paren_m.group(1)
            registry[inner.lower()] = canonical
            # Also register the name without parenthetical
            without_paren = canonical[:paren_m.start()].strip()
            if without_paren:
                registry[without_paren.lower()] = canonical

        # Register "slash" parts: "ProPublica Nonprofit Explorer / IRS 990"
        if " / " in canonical:
            for part in canonical.split(" / "):
                part = part.strip()
                if part:
                    registry[part.lower()] = canonical

        # Key short names for common sources
        slug = entry.rel_path.rsplit("/", 1)[-1].replace(".md", "")
        registry[slug.lower()] = canonical
    return registry


def match_reference(ref_text: str, registry: dict[str, str]) -> str | None:
    """Fuzzy-match a cross-reference mention against the name registry.

    Returns the canonical name if matched, else None.
    """
    lower = ref_text.lower()

    # 1. Exact match
    if lower in registry:
        return registry[lower]

    # 2. Strip parenthetical from ref and try again
    paren_m = re.search(r"\(([^)]+)\)", ref_text)
    if paren_m:
        inner = paren_m.group(1).lower()
        if inner in registry:
            return registry[inner]
        without = ref_text[:paren_m.start()].strip().lower()
        if without in registry:
            return registry[without]

    # 3. Check if ref_text is a substring of any registry key or vice versa
    for key, canonical in registry.items():
        if lower in key or key in lower:
            return canonical

    # 4. Token overlap: if 2+ significant tokens match
    ref_tokens = set(re.findall(r"[a-z]{3,}", lower))
    # Exclude very generic tokens
    generic = {"the", "and", "for", "with", "from", "data", "state", "local", "federal"}
    ref_tokens -= generic
    if len(ref_tokens) >= 2:
        best_match: str | None = None
        best_overlap = 0
        for key, canonical in registry.items():
            key_tokens = set(re.findall(r"[a-z]{3,}", key)) - generic
            overlap = len(ref_tokens & key_tokens)
            if overlap > best_overlap and overlap >= 2:
                best_overlap = overlap
                best_match = canonical
        if best_match:
            return best_match

    return None


# ---------------------------------------------------------------------------
# WikiGraphModel
# ---------------------------------------------------------------------------

class WikiGraphModel:
    """Manages a NetworkX graph of wiki data sources and their cross-references."""

    def __init__(self, wiki_dir: str | Path) -> None:
        self.wiki_dir = Path(wiki_dir)
        self.entries: list[WikiEntry] = []
        self._registry: dict[str, str] = {}
        self._graph: Any = None  # networkx.Graph
        self._layout: dict[str, tuple[float, float]] = {}
        self._dirty = True

    @property
    def graph(self) -> Any:
        if self._graph is None:
            self.rebuild()
        return self._graph

    @property
    def layout(self) -> dict[str, tuple[float, float]]:
        return self._layout

    def rebuild(self) -> None:
        """Parse wiki directory and rebuild the graph from scratch."""
        if nx is None:
            return

        self.entries = parse_index(self.wiki_dir)

        # Read cross-references from each entry file
        for entry in self.entries:
            file_path = self.wiki_dir / entry.rel_path
            title, refs = extract_cross_refs(file_path)
            entry.title = title
            entry.cross_refs = refs

        self._registry = _build_name_registry(self.entries)

        # Build graph
        g = nx.Graph()
        entry_names = {e.name for e in self.entries}

        for entry in self.entries:
            g.add_node(
                entry.name,
                category=entry.category,
                color=CATEGORY_COLORS.get(entry.category, DEFAULT_NODE_COLOR),
                title=entry.title or entry.name,
                path=entry.rel_path,
            )

        for entry in self.entries:
            for ref_text in entry.cross_refs:
                target = match_reference(ref_text, self._registry)
                if target and target in entry_names and target != entry.name:
                    if not g.has_edge(entry.name, target):
                        g.add_edge(entry.name, target, ref_text=ref_text)

        self._graph = g
        self._compute_layout()
        self._dirty = False

    def _compute_layout(self, width: int = 80, height: int = 30) -> None:
        """Compute spring layout scaled to character-cell dimensions."""
        if nx is None or self._graph is None or len(self._graph) == 0:
            self._layout = {}
            return

        # Use spring layout with some spacing.  spring_layout requires numpy;
        # if it is unavailable (or otherwise fails) fall back to a pure-Python
        # circular layout so the graph still renders.
        try:
            pos = nx.spring_layout(self._graph, seed=42, k=2.0)
        except Exception:
            pos = self._fallback_layout()

        # Scale to [1, width-2] x [1, height-2] (leaving border margin)
        xs = [p[0] for p in pos.values()]
        ys = [p[1] for p in pos.values()]
        if not xs:
            self._layout = {}
            return

        x_min, x_max = min(xs), max(xs)
        y_min, y_max = min(ys), max(ys)
        x_range = x_max - x_min or 1.0
        y_range = y_max - y_min or 1.0

        self._layout = {}
        for node, (x, y) in pos.items():
            nx_ = 2 + (x - x_min) / x_range * (width - 4)
            ny_ = 1 + (y - y_min) / y_range * (height - 3)
            self._layout[node] = (nx_, ny_)

    def _fallback_layout(self) -> dict[str, tuple[float, float]]:
        """Pure-Python circular layout used when numpy/spring_layout is absent.

        Returns the same ``{node: (x, y)}`` shape as ``nx.spring_layout`` with
        coordinates in roughly [-1, 1], so the downstream scaling is identical.
        """
        import math

        nodes = list(self._graph.nodes()) if self._graph is not None else []
        n = len(nodes)
        if n == 0:
            return {}
        if n == 1:
            return {nodes[0]: (0.0, 0.0)}
        return {
            node: (math.cos(2 * math.pi * i / n), math.sin(2 * math.pi * i / n))
            for i, node in enumerate(nodes)
        }

    @property
    def is_dirty(self) -> bool:
        return self._dirty

    def mark_dirty(self) -> None:
        self._dirty = True

    def node_count(self) -> int:
        if self._graph is None:
            return 0
        return len(self._graph)

    def edge_count(self) -> int:
        if self._graph is None:
            return 0
        return self._graph.number_of_edges()

    def render_to_buffer(self, width: int = 80, height: int = 30) -> list[list[tuple[str, str]]]:
        """Render the graph to a 2D buffer of (char, color) tuples.

        Uses Bresenham's line algorithm for edges and short labels for nodes.
        """
        if self._graph is None or len(self._graph) == 0:
            self.rebuild()

        # Recompute layout for given dimensions
        self._compute_layout(width, height)

        # Initialize buffer
        buf: list[list[tuple[str, str]]] = [
            [(" ", "dim")] * width for _ in range(height)
        ]

        if not self._layout:
            # No nodes — place a hint message
            msg = "No wiki entries found"
            row = height // 2
            col = max(0, (width - len(msg)) // 2)
            for i, ch in enumerate(msg):
                if col + i < width:
                    buf[row][col + i] = (ch, "dim")
            return buf

        # Draw edges first (so nodes overwrite)
        for u, v in self._graph.edges():
            if u in self._layout and v in self._layout:
                x1, y1 = self._layout[u]
                x2, y2 = self._layout[v]
                _draw_line(buf, int(x1), int(y1), int(x2), int(y2), width, height)

        # Draw nodes (short label, colored)
        for node in self._graph.nodes():
            if node not in self._layout:
                continue
            x, y = self._layout[node]
            ix, iy = int(x), int(y)
            color = self._graph.nodes[node].get("color", DEFAULT_NODE_COLOR)

            # Truncate label
            label = node[:12]
            # Center the label on the node position
            start_x = max(0, ix - len(label) // 2)

            # Place node marker
            if 0 <= iy < height and 0 <= ix < width:
                buf[iy][ix] = ("@", color)

            # Place label on the row above (or below if at top)
            label_y = iy - 1 if iy > 0 else iy + 1
            if 0 <= label_y < height:
                for i, ch in enumerate(label):
                    cx = start_x + i
                    if 0 <= cx < width:
                        buf[label_y][cx] = (ch, color)

        return buf


def _draw_line(
    buf: list[list[tuple[str, str]]],
    x0: int, y0: int, x1: int, y1: int,
    width: int, height: int,
) -> None:
    """Bresenham's line algorithm — draw dots for edges."""
    dx = abs(x1 - x0)
    dy = abs(y1 - y0)
    sx = 1 if x0 < x1 else -1
    sy = 1 if y0 < y1 else -1
    err = dx - dy

    while True:
        if 0 <= y0 < height and 0 <= x0 < width:
            # Only draw if cell is empty (space)
            if buf[y0][x0][0] == " ":
                buf[y0][x0] = (".", "dim")
        if x0 == x1 and y0 == y1:
            break
        e2 = 2 * err
        if e2 > -dy:
            err -= dy
            x0 += sx
        if e2 < dx:
            err += dx
            y0 += sy


# ---------------------------------------------------------------------------
# Filesystem watcher
# ---------------------------------------------------------------------------

class WikiWatcher:
    """Background thread that polls the wiki directory for changes."""

    def __init__(self, wiki_dir: str | Path, interval: float = 2.0) -> None:
        self.wiki_dir = Path(wiki_dir)
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._on_change: Any = None  # callback
        self._last_snapshot: dict[str, float] = {}

    def start(self, on_change: Any = None) -> None:
        """Start watching. on_change() is called (no args) when files change."""
        self._on_change = on_change
        self._last_snapshot = self._snapshot()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def _snapshot(self) -> dict[str, float]:
        """Return {relative_path: mtime} for all .md files in wiki dir."""
        result: dict[str, float] = {}
        if not self.wiki_dir.is_dir():
            return result
        for root, _dirs, files in os.walk(self.wiki_dir):
            for fname in files:
                if not fname.endswith(".md"):
                    continue
                full = os.path.join(root, fname)
                try:
                    result[full] = os.path.getmtime(full)
                except OSError:
                    pass
        return result

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(self.interval)
            if self._stop_event.is_set():
                break
            new_snap = self._snapshot()
            if new_snap != self._last_snapshot:
                self._last_snapshot = new_snap
                if self._on_change is not None:
                    try:
                        self._on_change()
                    except Exception:
                        pass
