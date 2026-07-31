"""Task graph and PoC memory."""

from __future__ import annotations

from easyhunt.knowledge.findings import Finding, PoC, Severity
from easyhunt.knowledge.memory import MemoryEntry, PoCMemory
from easyhunt.knowledge.taskgraph import TaskGraph, TaskState


class TestTaskGraph:
    def test_spawn_and_ready(self) -> None:
        graph = TaskGraph()
        task = graph.spawn("takeover_verify", "cdn.example.com", reason="dangling CNAME", priority=9)
        assert graph.ready()[0].id == task.id

    def test_duplicate_spawn_is_not_duplicated(self) -> None:
        graph = TaskGraph()
        first = graph.spawn("http_probe", "www.example.com")
        second = graph.spawn("http_probe", "www.example.com")
        assert first.id == second.id and len(graph) == 1

    def test_dependencies_gate_readiness(self) -> None:
        graph = TaskGraph()
        upstream = graph.spawn("dns_resolve", "example.com")
        downstream = graph.spawn("http_probe", "example.com", depends_on=[upstream.id])
        assert [t.id for t in graph.ready()] == [upstream.id]

        graph.complete(upstream.id, "resolved 12 hosts")
        assert downstream.id in [t.id for t in graph.ready()]

    def test_priority_ordering(self) -> None:
        graph = TaskGraph()
        graph.spawn("http_probe", "a.example.com", priority=3)
        graph.spawn("takeover_verify", "b.example.com", priority=9)
        assert graph.next_task().tool == "takeover_verify"

    def test_state_transitions(self) -> None:
        graph = TaskGraph()
        task = graph.spawn("nuclei_scan", "www.example.com")
        graph.start(task.id)
        assert task.state is TaskState.RUNNING
        graph.complete(task.id, "3 candidates")
        assert task.state is TaskState.DONE and task.terminal

    def test_blocked_task_records_why(self) -> None:
        graph = TaskGraph()
        task = graph.spawn("port_scan", "blog.example.com")
        graph.block(task.id, "refused: out of scope")
        assert task.state is TaskState.BLOCKED
        assert "out of scope" in task.error

    def test_terminal_tasks_are_not_ready(self) -> None:
        graph = TaskGraph()
        task = graph.spawn("http_probe", "www.example.com")
        graph.complete(task.id)
        assert graph.ready() == []

    def test_mermaid_renders_states(self) -> None:
        graph = TaskGraph()
        done = graph.spawn("dns_resolve", "example.com")
        graph.complete(done.id)
        graph.spawn("takeover_verify", "cdn.example.com", depends_on=[done.id])
        mermaid = graph.to_mermaid()
        assert mermaid.startswith("flowchart TD")
        assert "✓ dns_resolve" in mermaid and "-->" in mermaid

    def test_round_trips_through_disk(self, tmp_path) -> None:
        path = tmp_path / "taskgraph.json"
        graph = TaskGraph(path)
        graph.spawn("http_probe", "www.example.com", reason="new subdomain")
        graph.save()
        assert len(TaskGraph(path)) == 1


class TestAutoSpawn:
    def test_dangling_cname_enqueues_takeover_verify(self) -> None:
        graph = TaskGraph()
        tasks = graph.on_discovery("dangling_cname", "cdn.example.com", source="dns_resolve")
        assert [t.tool for t in tasks] == ["takeover_verify"]
        assert "dangling" in tasks[0].reason

    def test_js_bundle_enqueues_analysis(self) -> None:
        graph = TaskGraph()
        tasks = graph.on_discovery("js_bundle", "https://www.example.com/app.js")
        assert tasks[0].tool == "js_analyze"

    def test_validated_secret_is_top_priority(self) -> None:
        graph = TaskGraph()
        secret = graph.on_discovery("validated_secret", "config.py")[0]
        subdomain = graph.on_discovery("subdomain", "a.example.com")[0]
        assert secret.priority > subdomain.priority
        assert graph.next_task().id == secret.id

    def test_unknown_discovery_spawns_nothing(self) -> None:
        graph = TaskGraph()
        assert graph.on_discovery("something_new", "x") == []

    def test_every_spawned_task_carries_a_reason(self) -> None:
        graph = TaskGraph()
        for kind in ("dangling_cname", "subdomain", "js_bundle", "open_port", "storage_bucket"):
            for task in graph.on_discovery(kind, f"{kind}.example.com"):
                assert task.reason, f"{kind} spawned a task with no stated reason"


class TestEngagementIntegration:
    def test_discovery_spawns_and_audits(self, engagement) -> None:
        tasks = engagement.discovered("dangling_cname", "cdn.example.com", source="dns_resolve")
        assert tasks and engagement.taskgraph.next_task().tool == "takeover_verify"
        spawned = [r for r in engagement.audit.read_all() if r["event"] == "tasks_spawned"]
        assert spawned and spawned[-1]["discovery"] == "dangling_cname"

    def test_taskgraph_appears_in_status(self, engagement) -> None:
        engagement.discovered("subdomain", "a.example.com")
        assert engagement.summary()["taskgraph"]["total"] == 1

    def test_finish_persists_the_graph(self, engagement) -> None:
        engagement.discovered("subdomain", "a.example.com")
        engagement.finish()
        assert (engagement.workspace / "taskgraph.json").exists()


class TestPoCMemory:
    def test_remembers_and_recalls(self, tmp_path) -> None:
        memory = PoCMemory(tmp_path / "memory.jsonl")
        memory.remember(
            MemoryEntry(
                vuln_class="ssrf",
                technique="Blind SSRF via webhook URL parameter",
                reproduction="POST /api/webhook with url={CALLBACK}",
                context=["nodejs", "express"],
            )
        )
        matches = memory.recall("ssrf webhook")
        assert matches and matches[0]["technique"].startswith("Blind SSRF")

    def test_recall_filters_by_class(self, tmp_path) -> None:
        memory = PoCMemory(tmp_path / "memory.jsonl")
        memory.remember(MemoryEntry(vuln_class="ssrf", technique="a", reproduction="x"))
        memory.remember(MemoryEntry(vuln_class="xss", technique="b", reproduction="y"))
        assert len(memory.recall("a b", vuln_class="ssrf")) == 1

    def test_only_confirmed_findings_are_remembered(self, tmp_path) -> None:
        memory = PoCMemory(tmp_path / "memory.jsonl")
        candidate = Finding(asset="https://www.example.com/x", title="Maybe SSRF", severity=Severity.HIGH)
        assert memory.remember_finding(candidate) is None
        assert len(memory) == 0

    def test_confirmed_finding_is_generalized(self, tmp_path) -> None:
        memory = PoCMemory(tmp_path / "memory.jsonl")
        finding = Finding(
            asset="https://secret-client.example.com/api",
            title="SSRF in webhook",
            rule_id="ssrf.webhook",
            severity=Severity.HIGH,
        )
        finding.confirm(
            PoC(
                reproduction="curl https://secret-client.example.com/api?url=http://169.254.169.254/",
                expected_result="metadata response",
                observed_result="IAM credentials returned",
            )
        )
        entry = memory.remember_finding(finding, engagement_name="test")
        # The client's hostname must not be carried into cross-engagement memory.
        assert "secret-client.example.com" not in entry.reproduction
        assert "{TARGET_HOST}" in entry.reproduction

    def test_repeat_remember_increments_uses(self, tmp_path) -> None:
        memory = PoCMemory(tmp_path / "memory.jsonl")
        entry = MemoryEntry(vuln_class="xss", technique="reflected in search", reproduction="?q=<svg>")
        memory.remember(entry)
        memory.remember(MemoryEntry(vuln_class="xss", technique="reflected in search", reproduction="?q=<svg>"))
        assert memory.recall("reflected")[0]["uses"] == 1

    def test_survives_a_restart(self, tmp_path) -> None:
        path = tmp_path / "memory.jsonl"
        PoCMemory(path).remember(MemoryEntry(vuln_class="idor", technique="sequential id", reproduction="GET /u/2"))
        assert len(PoCMemory(path)) == 1

    def test_empty_recall_is_safe(self, tmp_path) -> None:
        assert PoCMemory(tmp_path / "memory.jsonl").recall("anything") == []

    def test_engagement_finish_records_confirmed_techniques(self, engagement) -> None:
        finding = Finding(
            asset="https://www.example.com/x",
            title="Exposed .env",
            rule_id="exposure.env",
            severity=Severity.HIGH,
        )
        finding.confirm(
            PoC(reproduction="curl https://www.example.com/.env", expected_result="200", observed_result="200 with keys")
        )
        engagement.findings.add(finding)
        summary = engagement.finish()
        assert summary["memory"]["techniques_remembered"] == 1
