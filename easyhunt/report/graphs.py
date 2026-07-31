"""Graph rendering for reports: SVG always, PNG and DOT when tools allow.

A report that says "a public Lambda reaches customer data in two hops" is
convincing. A picture of it is what gets forwarded to the person who can approve
the fix, so the export path matters more than it first appears.

Three formats, in order of how reliably they are produced:

* **SVG** — always. Rendered by a small layered-DAG layout in this module with no
  dependencies at all, because a report artifact that only exists when Graphviz
  happens to be installed is an artifact you cannot rely on. Scales cleanly, and
  every platform a bug bounty report lands on can display it.
* **DOT** — always. Text, so it costs nothing to emit and lets anyone re-render
  with better layout than this file implements.
* **PNG** — when `dot`, `rsvg-convert`, `cairosvg`, or ImageMagick is present.
  Some platforms still will not inline an SVG, which is the only reason to want
  a raster at all.

The layout is Sugiyama-lite: assign layers by longest path from a root, order
within each layer to reduce crossings, place on a grid. It is not Graphviz. For
the twenty-to-sixty-node graphs a report contains, it is legible, and being
dependency-free is worth more here than being optimal.
"""

from __future__ import annotations

import html
import logging
import shutil
import subprocess
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("easyhunt.report.graphs")

__all__ = ["GraphRender", "render_attack_paths", "render_task_graph"]

# Severity-driven palette, readable on both light and dark backgrounds.
PALETTE = {
    "critical": ("#7f1d1d", "#fecaca"),
    "high": ("#9a3412", "#fed7aa"),
    "medium": ("#854d0e", "#fef08a"),
    "low": ("#1e40af", "#bfdbfe"),
    "info": ("#374151", "#e5e7eb"),
    "done": ("#166534", "#bbf7d0"),
    "running": ("#1e40af", "#bfdbfe"),
    "pending": ("#374151", "#f3f4f6"),
    "blocked": ("#7f1d1d", "#fecaca"),
    "failed": ("#7f1d1d", "#fecaca"),
    "skipped": ("#6b7280", "#f9fafb"),
    "entry": ("#7c2d12", "#fed7aa"),
    "target": ("#7f1d1d", "#fecaca"),
    "default": ("#374151", "#f3f4f6"),
}

NODE_WIDTH = 190
NODE_HEIGHT = 52
LAYER_GAP = 110
NODE_GAP = 26


@dataclass
class RenderNode:
    id: str
    label: str
    sublabel: str = ""
    style: str = "default"
    layer: int = 0
    x: float = 0.0
    y: float = 0.0


@dataclass
class RenderEdge:
    source: str
    target: str
    label: str = ""
    dashed: bool = False


@dataclass
class GraphRender:
    """A laid-out graph, ready to serialize."""

    nodes: list[RenderNode] = field(default_factory=list)
    edges: list[RenderEdge] = field(default_factory=list)
    title: str = ""

    def layout(self) -> GraphRender:
        """Assign layers and coordinates. Idempotent."""
        if not self.nodes:
            # An engagement with nothing to draw is a normal outcome, not an
            # error — a report must still be produced.
            return self
        by_id = {n.id: n for n in self.nodes}
        incoming: dict[str, list[str]] = defaultdict(list)
        outgoing: dict[str, list[str]] = defaultdict(list)
        for edge in self.edges:
            if edge.source in by_id and edge.target in by_id:
                outgoing[edge.source].append(edge.target)
                incoming[edge.target].append(edge.source)

        # Layer = longest path from any root, computed iteratively so a cycle
        # cannot hang the layout (security graphs do contain cycles).
        roots = [n.id for n in self.nodes if not incoming[n.id]] or [self.nodes[0].id]
        layers: dict[str, int] = dict.fromkeys(roots, 0)
        for _ in range(len(self.nodes)):
            changed = False
            for edge in self.edges:
                if edge.source in layers:
                    candidate = layers[edge.source] + 1
                    if candidate > layers.get(edge.target, -1):
                        layers[edge.target] = candidate
                        changed = True
            if not changed:
                break
        for node in self.nodes:
            node.layer = layers.get(node.id, 0)

        # Order within a layer by barycentre of predecessors, which removes most
        # crossings for the shapes these graphs actually take.
        by_layer: dict[int, list[RenderNode]] = defaultdict(list)
        for node in self.nodes:
            by_layer[node.layer].append(node)

        positions: dict[str, int] = {}
        for layer in sorted(by_layer):
            members = by_layer[layer]
            if layer > 0:
                members.sort(
                    key=lambda n: (
                        sum(positions.get(p, 0) for p in incoming[n.id]) / max(1, len(incoming[n.id])),
                        n.label,
                    )
                )
            else:
                members.sort(key=lambda n: n.label)
            for index, node in enumerate(members):
                positions[node.id] = index
                node.x = 40 + index * (NODE_WIDTH + NODE_GAP)
                node.y = 60 + layer * (NODE_HEIGHT + LAYER_GAP)
        return self

    @property
    def width(self) -> float:
        return max([n.x + NODE_WIDTH for n in self.nodes], default=400) + 40

    @property
    def height(self) -> float:
        return max([n.y + NODE_HEIGHT for n in self.nodes], default=200) + 40

    # -- serialization ------------------------------------------------------ #

    def to_svg(self) -> str:
        """Self-contained SVG. No external fonts, no scripts, no dependencies."""
        self.layout()
        by_id = {n.id: n for n in self.nodes}
        parts: list[str] = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.width:.0f}" '
            f'height="{self.height:.0f}" viewBox="0 0 {self.width:.0f} {self.height:.0f}" '
            'font-family="ui-sans-serif,system-ui,-apple-system,Segoe UI,Helvetica,sans-serif">',
            '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
            'markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
            '<path d="M 0 0 L 10 5 L 0 10 z" fill="#6b7280"/></marker></defs>',
            f'<rect width="{self.width:.0f}" height="{self.height:.0f}" fill="#ffffff"/>',
        ]
        if self.title:
            parts.append(
                f'<text x="20" y="32" font-size="17" font-weight="600" fill="#111827">'
                f"{html.escape(self.title)}</text>"
            )

        # Edges first so nodes paint over the line ends.
        for edge in self.edges:
            source, target = by_id.get(edge.source), by_id.get(edge.target)
            if not source or not target:
                continue
            x1, y1 = source.x + NODE_WIDTH / 2, source.y + NODE_HEIGHT
            x2, y2 = target.x + NODE_WIDTH / 2, target.y
            mid = (y1 + y2) / 2
            dash = ' stroke-dasharray="5,4"' if edge.dashed else ""
            parts.append(
                f'<path d="M {x1:.0f} {y1:.0f} C {x1:.0f} {mid:.0f}, {x2:.0f} {mid:.0f}, '
                f'{x2:.0f} {y2:.0f}" fill="none" stroke="#9ca3af" stroke-width="1.5"'
                f'{dash} marker-end="url(#arrow)"/>'
            )
            if edge.label:
                parts.append(
                    f'<text x="{(x1 + x2) / 2:.0f}" y="{mid:.0f}" font-size="11" '
                    f'fill="#6b7280" text-anchor="middle">{html.escape(edge.label[:26])}</text>'
                )

        for node in self.nodes:
            stroke, fill = PALETTE.get(node.style, PALETTE["default"])
            parts.append(
                f'<rect x="{node.x:.0f}" y="{node.y:.0f}" width="{NODE_WIDTH}" '
                f'height="{NODE_HEIGHT}" rx="8" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>'
            )
            parts.append(
                f'<text x="{node.x + NODE_WIDTH / 2:.0f}" y="{node.y + 22:.0f}" font-size="12.5" '
                f'font-weight="600" fill="{stroke}" text-anchor="middle">'
                f"{html.escape(_truncate(node.label, 26))}</text>"
            )
            if node.sublabel:
                parts.append(
                    f'<text x="{node.x + NODE_WIDTH / 2:.0f}" y="{node.y + 39:.0f}" '
                    f'font-size="10.5" fill="{stroke}" opacity="0.75" text-anchor="middle">'
                    f"{html.escape(_truncate(node.sublabel, 30))}</text>"
                )

        parts.append("</svg>")
        return "\n".join(parts)

    def to_dot(self) -> str:
        """Graphviz DOT, so anyone can re-render with a real layout engine."""
        lines = [
            "digraph easyhunt {",
            "  rankdir=TB;",
            '  node [shape=box style="rounded,filled" fontname="Helvetica" fontsize=11];',
            '  edge [fontname="Helvetica" fontsize=9 color="#9ca3af"];',
        ]
        if self.title:
            lines.append(f'  label="{_dot_escape(self.title)}"; labelloc=t; fontsize=15;')
        for node in self.nodes:
            stroke, fill = PALETTE.get(node.style, PALETTE["default"])
            label = _dot_escape(node.label)
            if node.sublabel:
                label += f"\\n{_dot_escape(node.sublabel)}"
            lines.append(
                f'  "{_dot_escape(node.id)}" [label="{label}" fillcolor="{fill}" '
                f'color="{stroke}" fontcolor="{stroke}"];'
            )
        for edge in self.edges:
            style = ' style=dashed' if edge.dashed else ""
            label = f' label="{_dot_escape(edge.label)}"' if edge.label else ""
            lines.append(
                f'  "{_dot_escape(edge.source)}" -> "{_dot_escape(edge.target)}"{label}{style};'
            )
        lines.append("}")
        return "\n".join(lines)

    def write(self, base: Path, *, png: bool = True) -> dict[str, str]:
        """Write .svg and .dot, plus .png when a converter is available."""
        base.parent.mkdir(parents=True, exist_ok=True)
        written: dict[str, str] = {}

        svg_path = base.with_suffix(".svg")
        svg_path.write_text(self.to_svg(), encoding="utf-8")
        written["svg"] = str(svg_path)

        dot_path = base.with_suffix(".dot")
        dot_path.write_text(self.to_dot(), encoding="utf-8")
        written["dot"] = str(dot_path)

        if png:
            png_path = _to_png(svg_path, dot_path, base.with_suffix(".png"))
            if png_path:
                written["png"] = str(png_path)
        return written


def _truncate(text: str, limit: int) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _dot_escape(text: str) -> str:
    return (text or "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _to_png(svg: Path, dot: Path, out: Path) -> Path | None:
    """Try each available converter. Returns the PNG path, or None.

    PNG is genuinely optional — the SVG is the artifact the report links, so a
    machine with no converter loses nothing important.
    """
    attempts: list[tuple[str, list[str]]] = []
    if shutil.which("dot"):
        attempts.append(("graphviz", ["dot", "-Tpng", str(dot), "-o", str(out)]))
    if shutil.which("rsvg-convert"):
        attempts.append(("rsvg", ["rsvg-convert", "-o", str(out), str(svg)]))
    if shutil.which("convert"):
        attempts.append(("imagemagick", ["convert", str(svg), str(out)]))
    if shutil.which("inkscape"):
        attempts.append(("inkscape", ["inkscape", str(svg), "-o", str(out)]))

    for name, command in attempts:
        try:
            proc = subprocess.run(  # noqa: S603
                command, capture_output=True, timeout=60, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.debug("png via %s failed: %s", name, exc)
            continue
        if proc.returncode == 0 and out.exists() and out.stat().st_size > 0:
            return out

    try:  # pure-Python fallback
        import cairosvg  # noqa: PLC0415

        cairosvg.svg2png(url=str(svg), write_to=str(out))
        if out.exists():
            return out
    except Exception as exc:  # noqa: BLE001
        log.debug("png via cairosvg failed: %s", exc)

    log.info(
        "no PNG converter available (tried dot, rsvg-convert, convert, inkscape, "
        "cairosvg) — the SVG is written and is what the report links"
    )
    return None


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #


def render_task_graph(taskgraph: Any, *, max_nodes: int = 50) -> GraphRender:
    """The task graph: what was done, and which discovery caused it."""
    tasks = sorted(taskgraph.all(), key=lambda t: t.created_at)[:max_nodes]
    known = {t.id for t in tasks}

    render = GraphRender(title="Engagement task graph")
    for task in tasks:
        render.nodes.append(
            RenderNode(
                id=task.id,
                label=task.tool,
                sublabel=task.target,
                style=task.state.value,
            )
        )
    for task in tasks:
        for dependency in task.depends_on:
            if dependency in known:
                render.edges.append(RenderEdge(source=dependency, target=task.id))
        # Show the discovery that spawned this task, as a dashed edge.
        if task.spawned_by:
            for other in tasks:
                if other.tool == task.spawned_by and other.id != task.id:
                    render.edges.append(
                        RenderEdge(source=other.id, target=task.id, label="spawned", dashed=True)
                    )
                    break
    return render


def render_attack_paths(paths: Iterable[Any], *, max_paths: int = 12) -> GraphRender:
    """Cloud attack paths, entry points at the top, destinations at the bottom."""
    render = GraphRender(title="Cloud attack paths")
    seen: set[str] = set()
    seen_edges: set[tuple[str, str]] = set()

    for path in list(paths)[:max_paths]:
        nodes = path.nodes if hasattr(path, "nodes") else path["nodes"]
        edges = path.edges if hasattr(path, "edges") else path["edges"]

        for index, node in enumerate(nodes):
            node_id = node.id if hasattr(node, "id") else node["id"]
            if node_id in seen:
                continue
            seen.add(node_id)
            kind = node.kind if hasattr(node, "kind") else node["kind"]
            name = node.name if hasattr(node, "name") else node["name"]
            entry = node.entry_point if hasattr(node, "entry_point") else node.get("entry_point")
            style = "entry" if entry else ("target" if index == len(nodes) - 1 else "info")
            render.nodes.append(
                RenderNode(id=node_id, label=name or node_id, sublabel=kind, style=style)
            )

        for edge in edges:
            source = edge.source if hasattr(edge, "source") else edge["source"]
            target = edge.target if hasattr(edge, "target") else edge["target"]
            relation = edge.relation if hasattr(edge, "relation") else edge["relation"]
            if (source, target) in seen_edges:
                continue
            seen_edges.add((source, target))
            render.edges.append(
                RenderEdge(source=source, target=target, label=relation.replace("_", " "))
            )
    return render


def render_graph_memory(memory: Any, subject: str, *, depth: int = 1) -> GraphRender | None:
    """What is known about one subject, as a picture."""
    recalled = memory.recall(subject, depth=depth)
    if not recalled.get("known"):
        return None

    root = recalled["entity"]
    render = GraphRender(title=f"Known: {root['name'] or root['id']}")
    render.nodes.append(
        RenderNode(id=root["id"], label=root["name"] or root["id"], sublabel=root["kind"], style="entry")
    )
    for item in recalled["neighbourhood"]:
        entity = item["entity"]
        style = "high" if entity["kind"] == "finding" else "info"
        render.nodes.append(
            RenderNode(id=entity["id"], label=entity["name"] or entity["id"],
                       sublabel=entity["kind"], style=style)
        )
        if item["direction"] == "out":
            render.edges.append(RenderEdge(root["id"], entity["id"], item["relation"]))
        else:
            render.edges.append(RenderEdge(entity["id"], root["id"], item["relation"]))
    return render
