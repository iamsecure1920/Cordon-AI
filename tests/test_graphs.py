"""Attack-path graph, graph memory, and rendered exports."""

from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from cordon.knowledge.attackgraph import (
    AttackGraph,
    Edge,
    Node,
    build_from_prowler,
)
from cordon.knowledge.graphmemory import (
    Entity,
    GraphMemory,
    ingest_engagement,
    relations_from_dns,
)
from cordon.knowledge.taskgraph import TaskGraph
from cordon.report.graphs import (
    GraphRender,
    RenderEdge,
    RenderNode,
    render_attack_paths,
    render_graph_memory,
    render_task_graph,
)


def lambda_to_data() -> AttackGraph:
    """public Lambda → execution role → customer data. The canonical chain."""
    graph = AttackGraph()
    graph.add_node(
        Node(id="fn", kind="function", name="api-handler", entry_point=True,
             exposure="public_unauthenticated")
    )
    graph.add_node(Node(id="role", kind="role", name="lambda-exec"))
    graph.add_node(Node(id="bucket", kind="data_store", name="customer-exports"))
    graph.add_edge(Edge("fn", "role", "assumes", "execution role"))
    graph.add_edge(Edge("role", "bucket", "reads", "s3:GetObject on *"))
    return graph


class TestAttackGraph:
    def test_finds_the_path_to_data(self) -> None:
        paths = lambda_to_data().find_paths()
        best = paths[0]
        assert best.entry.name == "api-handler"
        assert best.target.name == "customer-exports"
        assert best.hops == 2

    def test_narrative_reads_as_a_sentence(self) -> None:
        narrative = lambda_to_data().find_paths()[0].narrative()
        assert "api-handler" in narrative and "→ reads" in narrative

    def test_reachable_data_is_critical(self) -> None:
        from cordon.knowledge.findings import Severity

        assert lambda_to_data().find_paths()[0].severity is Severity.CRITICAL

    def test_a_path_needs_an_entry_point(self) -> None:
        graph = lambda_to_data()
        graph.nodes["fn"].entry_point = False
        # Nothing is reachable from outside, so there is no attack path.
        assert graph.find_paths() == []

    def test_valuable_destination_beats_a_shorter_worthless_one(self) -> None:
        graph = lambda_to_data()
        graph.add_node(Node(id="q", kind="queue", name="dev-queue"))
        graph.add_edge(Edge("fn", "q", "reads", "one hop"))
        paths = graph.find_paths(min_target_value=0)
        # Two hops to customer data outranks one hop to a dev queue.
        assert paths[0].target.name == "customer-exports"

    def test_structural_edges_are_not_traversed(self) -> None:
        graph = AttackGraph()
        graph.add_node(Node(id="a", kind="compute", name="a", entry_point=True))
        graph.add_node(Node(id="b", kind="data_store", name="b"))
        # 'tagged_with' is not a movement relation.
        graph.add_edge(Edge("a", "b", "tagged_with", "metadata only"))
        assert graph.find_paths() == []

    def test_cycles_do_not_hang_the_search(self) -> None:
        graph = AttackGraph()
        graph.add_node(Node(id="a", kind="role", name="a", entry_point=True))
        graph.add_node(Node(id="b", kind="role", name="b"))
        graph.add_edge(Edge("a", "b", "assumes"))
        graph.add_edge(Edge("b", "a", "assumes"))
        assert isinstance(graph.find_paths(max_hops=6), list)

    def test_hop_limit_is_respected(self) -> None:
        graph = AttackGraph()
        graph.add_node(Node(id="n0", kind="compute", name="n0", entry_point=True))
        for index in range(1, 9):
            graph.add_node(Node(id=f"n{index}", kind="role", name=f"n{index}"))
            graph.add_edge(Edge(f"n{index - 1}", f"n{index}", "assumes"))
        assert all(p.hops <= 3 for p in graph.find_paths(max_hops=3))

    def test_builds_from_prowler_records(self) -> None:
        records = [
            {
                "finding_info": {"uid": "s3_bucket_public_access", "title": "Bucket is public"},
                "severity": "high",
                "resources": [{"uid": "arn:aws:s3:::exports", "name": "exports", "type": "AwsS3Bucket"}],
            },
            {
                "finding_info": {"uid": "iam_role_administratoraccess", "title": "Role has AdministratorAccess"},
                "severity": "critical",
                "resources": [{"uid": "arn:aws:iam::1:role/app", "name": "app", "type": "AwsIamRole"}],
            },
        ]
        graph = build_from_prowler(records)
        assert len(graph) >= 2
        # The public bucket is inferred as an entry point.
        assert any(n.entry_point for n in graph.nodes.values())
        # The admin control failure implies an escalation edge.
        assert any(e.relation == "can_escalate_to" for e in graph.edges)

    def test_empty_input_is_safe(self) -> None:
        assert build_from_prowler([]).find_paths() == []

    def test_stats_and_serialization(self, tmp_path: Path) -> None:
        graph = lambda_to_data()
        stats = graph.stats()
        assert stats["nodes"] == 3 and stats["entry_points"] == 1
        path = graph.save(tmp_path / "g.json")
        assert path.exists()


class TestGraphMemory:
    def test_recall_answers_what_do_i_know(self, tmp_path: Path) -> None:
        memory = GraphMemory(tmp_path / "g.json", engagement="test")
        relations_from_dns(memory, [{"host": "api.example.com", "a": ["203.0.113.7"], "cname": []}])
        memory.observe(Entity(id="tech:nginx", kind="technology", name="nginx"))
        memory.relate("host:api.example.com", "runs", "tech:nginx", observed_by="httpx")

        recalled = memory.recall("api.example.com")
        assert recalled["known"]
        relations = {n["relation"] for n in recalled["neighbourhood"]}
        assert relations == {"resolves_to", "runs"}
        assert "api.example.com" in recalled["summary"]

    def test_unknown_subject_says_so(self, tmp_path: Path) -> None:
        memory = GraphMemory(tmp_path / "g.json")
        assert memory.recall("never-seen.example.com")["known"] is False

    def test_unknown_relations_are_rejected(self, tmp_path: Path) -> None:
        # A closed vocabulary is what keeps recall predictable.
        memory = GraphMemory(tmp_path / "g.json")
        assert memory.relate("a", "points_at", "b") is None
        assert memory.relate("a", "resolves_to", "b") is not None

    def test_dangling_cname_is_visible_in_the_graph(self, tmp_path: Path) -> None:
        memory = GraphMemory(tmp_path / "g.json")
        relations_from_dns(
            memory, [{"host": "cdn.example.com", "a": [], "cname": ["old.s3.amazonaws.com"]}]
        )
        recalled = memory.recall("cdn.example.com")
        # Delegation with no resolves_to alongside it is the takeover shape.
        relations = {n["relation"] for n in recalled["neighbourhood"]}
        assert relations == {"delegates_to"}

    def test_findings_attach_to_their_asset(self, tmp_path: Path, engagement) -> None:
        from cordon.knowledge.findings import Finding, Severity

        engagement.findings.add(
            Finding(
                asset="https://www.example.com/.env",
                title="Exposed .env",
                severity=Severity.HIGH,
                source_tool="nuclei",
            )
        )
        memory = GraphMemory(tmp_path / "g.json")
        ingest_engagement(memory, engagement)
        recalled = memory.recall("https://www.example.com/.env")
        assert recalled["known"]
        assert recalled["related_findings"]

    def test_depth_two_reaches_further(self, tmp_path: Path) -> None:
        memory = GraphMemory(tmp_path / "g.json")
        memory.relate("host:a", "resolves_to", "ip:1")
        memory.relate("ip:1", "hosts", "host:b")
        assert len(memory.recall("host:a", depth=1)["neighbourhood"]) == 1
        assert len(memory.recall("host:a", depth=2)["neighbourhood"]) == 2

    def test_survives_a_restart(self, tmp_path: Path) -> None:
        path = tmp_path / "g.json"
        first = GraphMemory(path, engagement="test")
        first.relate("host:a.example.com", "resolves_to", "ip:203.0.113.1")
        first.save()
        assert GraphMemory(path).recall("a.example.com")["known"]

    def test_duplicate_relationships_collapse(self, tmp_path: Path) -> None:
        memory = GraphMemory(tmp_path / "g.json")
        for _ in range(5):
            memory.relate("host:a", "resolves_to", "ip:1")
        assert memory.stats()["relationships"] == 1

    def test_engagement_exposes_graph_memory(self, engagement) -> None:
        assert engagement.graph.stats()["backend"] == "native"

    def test_finish_indexes_the_engagement(self, engagement) -> None:
        from cordon.knowledge.findings import Asset

        engagement.assets.add(Asset(value="api.example.com", kind="subdomain", source="bbot"))
        summary = engagement.finish()
        assert summary["graph_memory"]["indexed"]["assets"] == 1
        assert (engagement.workspace / "graph-memory.json").exists()


class TestRendering:
    def test_svg_is_well_formed_xml(self, tmp_path: Path) -> None:
        svg = render_attack_paths(lambda_to_data().find_paths()).to_svg()
        ET.fromstring(svg)  # noqa: S314 — our own generated markup
        assert svg.startswith("<svg") and svg.rstrip().endswith("</svg>")

    def test_svg_escapes_hostile_labels(self) -> None:
        # Node labels come from target-controlled data; they must not break out.
        render = GraphRender(nodes=[RenderNode(id="x", label='<script>alert(1)</script>')])
        svg = render.to_svg()
        assert "<script>" not in svg
        assert "&lt;script&gt;" in svg
        ET.fromstring(svg)  # noqa: S314

    def test_dot_escapes_quotes(self) -> None:
        render = GraphRender(nodes=[RenderNode(id='a"b', label='say "hi"')])
        dot = render.to_dot()
        assert '\\"' in dot and dot.strip().endswith("}")

    def test_layout_layers_by_depth(self) -> None:
        render = GraphRender(
            nodes=[RenderNode(id=str(i), label=str(i)) for i in range(3)],
            edges=[RenderEdge("0", "1"), RenderEdge("1", "2")],
        ).layout()
        layers = {n.id: n.layer for n in render.nodes}
        assert layers["0"] < layers["1"] < layers["2"]

    def test_layout_terminates_on_a_cycle(self) -> None:
        render = GraphRender(
            nodes=[RenderNode(id="a", label="a"), RenderNode(id="b", label="b")],
            edges=[RenderEdge("a", "b"), RenderEdge("b", "a")],
        ).layout()
        assert len(render.nodes) == 2

    def test_writes_svg_and_dot_always(self, tmp_path: Path) -> None:
        written = render_attack_paths(lambda_to_data().find_paths()).write(tmp_path / "ap")
        assert Path(written["svg"]).exists()
        assert Path(written["dot"]).exists()

    def test_png_is_a_real_png_when_a_converter_exists(self, tmp_path: Path) -> None:
        import shutil

        written = render_attack_paths(lambda_to_data().find_paths()).write(tmp_path / "ap")
        if "png" not in written:
            pytest.skip("no PNG converter installed (dot/rsvg-convert/convert/cairosvg)")
        assert shutil.which("dot") or shutil.which("convert") or True
        data = Path(written["png"]).read_bytes()
        assert data[:8] == b"\x89PNG\r\n\x1a\n"
        width, height = struct.unpack(">II", data[16:24])
        assert width > 0 and height > 0

    def test_task_graph_renders_with_state_colours(self, tmp_path: Path) -> None:
        graph = TaskGraph()
        first = graph.spawn("dns_resolve", "example.com")
        graph.complete(first.id)
        graph.spawn("takeover_verify", "cdn.example.com", depends_on=[first.id])
        svg = render_task_graph(graph).to_svg()
        assert "dns_resolve" in svg and "takeover_verify" in svg

    def test_graph_memory_renders(self, tmp_path: Path) -> None:
        memory = GraphMemory(tmp_path / "g.json")
        memory.relate("host:a.example.com", "resolves_to", "ip:203.0.113.1")
        render = render_graph_memory(memory, "a.example.com")
        assert render is not None
        ET.fromstring(render.to_svg())  # noqa: S314

    def test_unknown_subject_renders_nothing(self, tmp_path: Path) -> None:
        assert render_graph_memory(GraphMemory(tmp_path / "g.json"), "nope") is None

    def test_empty_graph_does_not_crash(self, tmp_path: Path) -> None:
        written = GraphRender(nodes=[], edges=[], title="empty").write(tmp_path / "e", png=False)
        ET.fromstring(Path(written["svg"]).read_text())  # noqa: S314


class TestReportIntegration:
    async def test_report_includes_rendered_graphs(self, engagement) -> None:
        from cordon.report.synthesize import generate_report

        engagement.discovered("dangling_cname", "cdn.example.com", source="dns_resolve")
        result = await generate_report(engagement, formats=["md"])
        assert "taskgraph_svg" in result["reports"]
        assert Path(result["reports"]["taskgraph_svg"]).exists()
        assert "taskgraph_dot" in result["reports"]

    async def test_attack_paths_reach_the_report(self, engagement) -> None:
        from cordon.knowledge.findings import Finding, Severity
        from cordon.report.synthesize import generate_report

        path = lambda_to_data().find_paths()[0]
        engagement.findings.add(
            Finding(
                asset="customer-exports",
                title="Attack path to customer data",
                severity=Severity.CRITICAL,
                extra={"path": path.to_dict()},
            )
        )
        result = await generate_report(engagement, formats=["md"])
        assert "attack_paths_svg" in result["reports"]
        svg = Path(result["reports"]["attack_paths_svg"]).read_text()
        assert "api-handler" in svg and "customer-exports" in svg
