"""Penetration task graph — a DAG of work with dependencies (VulnBot's pattern).

This is what makes a run feel like an investigation rather than a script. A
discovery does not just get logged; it *creates work*. A CNAME with nothing
behind it enqueues a takeover verification. A JavaScript bundle enqueues a secret
scan. An open admin panel enqueues an authorization review.

The graph is the agent's memory of what it meant to do. Without it, an agent that
finds forty subdomains in phase one has forgotten about thirty of them by phase
three — a failure mode that looks like thoroughness right up until you read the
report and notice the gaps.

Tasks are *proposals*, not permissions. A spawned task still goes through scope,
sanitize, budget, rate limit, and approval when it eventually runs. The graph
decides what is worth doing; the control plane decides what is allowed.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from easyhunt.util.parse import stable_id

__all__ = ["SPAWN_RULES", "Task", "TaskGraph", "TaskState"]


class TaskState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    BLOCKED = "blocked"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Task:
    """One unit of planned work."""

    #: The MCP tool that would carry this out.
    tool: str
    target: str
    phase: str = "unknown"
    id: str = ""
    state: TaskState = TaskState.PENDING
    #: Task ids that must reach DONE before this one is ready.
    depends_on: list[str] = field(default_factory=list)
    #: What discovery created this task. Shown in the report's methodology.
    reason: str = ""
    spawned_by: str | None = None
    #: Higher runs first among ready tasks.
    priority: int = 5
    args: dict[str, Any] = field(default_factory=dict)
    result_summary: str = ""
    error: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    started_at: str | None = None
    finished_at: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, TaskState):
            self.state = TaskState(str(self.state))
        if not self.id:
            self.id = f"{self.tool}:{stable_id(self.tool, self.target, json.dumps(self.args, sort_keys=True, default=str))}"

    @property
    def terminal(self) -> bool:
        return self.state in {TaskState.DONE, TaskState.FAILED, TaskState.SKIPPED}

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        return data


# What each kind of discovery should make the agent go and do next.
#
# Each rule is (discovery kind, predicate over the discovery, tool, phase,
# priority, reason template). Keeping these declarative means adding a new
# follow-up is a data change, and means the report can explain *why* every task
# in the graph exists.
SPAWN_RULES: list[dict[str, Any]] = [
    {
        "when": "dangling_cname",
        "tool": "takeover_verify",
        "phase": "takeover",
        "priority": 9,
        "reason": "CNAME resolves with no address record — possible dangling delegation",
    },
    {
        "when": "subdomain",
        "tool": "http_probe",
        "phase": "http_probe",
        "priority": 6,
        "reason": "New subdomain discovered — check for a live HTTP service",
    },
    {
        "when": "js_bundle",
        "tool": "js_analyze",
        "phase": "js_analysis",
        "priority": 7,
        "reason": "JavaScript bundle found — extract endpoints and credential candidates",
    },
    {
        "when": "admin_interface",
        "tool": "validate_findings",
        "phase": "exploit",
        "priority": 8,
        "reason": "Administrative interface reachable — review authentication and authorization",
    },
    {
        "when": "open_port",
        "tool": "service_scan",
        "phase": "ports",
        "priority": 5,
        "reason": "Open port found — fingerprint the service behind it",
    },
    {
        "when": "storage_bucket",
        "tool": "cloud_asset_discovery",
        "phase": "cloud",
        "priority": 7,
        "reason": "Cloud storage discovered — check whether it is publicly readable",
    },
    {
        "when": "validated_secret",
        "tool": "poc_record",
        "phase": "exploit",
        "priority": 10,
        "reason": "Credential validated as live — report immediately and request rotation",
    },
    {
        "when": "code_repository",
        "tool": "source_fetch",
        "phase": "secrets",
        "priority": 6,
        "reason": "Source repository found — clone and scan history for secrets",
    },
    {
        "when": "candidate_finding",
        "tool": "validate_findings",
        "phase": "exploit",
        "priority": 8,
        "reason": "Scanner candidate — needs a PoC before it can be reported",
    },
]


class TaskGraph:
    """A dependency-ordered work queue that grows as the engagement learns."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._tasks: dict[str, Task] = {}
        self._lock = threading.Lock()
        if path and path.exists():
            self.load(path)

    # -- mutation ----------------------------------------------------------- #

    def add(self, task: Task) -> Task:
        """Insert a task. Re-adding an identical task is a no-op, not a duplicate."""
        with self._lock:
            existing = self._tasks.get(task.id)
            if existing is not None:
                return existing
            self._tasks[task.id] = task
            return task

    def spawn(
        self,
        tool: str,
        target: str,
        *,
        reason: str = "",
        phase: str = "unknown",
        priority: int = 5,
        depends_on: Iterable[str] | None = None,
        spawned_by: str | None = None,
        **args: Any,
    ) -> Task:
        """Create a follow-up task. The main entry point for tools."""
        task = Task(
            tool=tool,
            target=target,
            phase=phase,
            reason=reason,
            priority=priority,
            depends_on=list(depends_on or []),
            spawned_by=spawned_by,
            args=args,
        )
        return self.add(task)

    def on_discovery(
        self, kind: str, value: str, *, source: str = "", detail: str = ""
    ) -> list[Task]:
        """Apply the spawn rules to one discovery. Returns the tasks created."""
        created: list[Task] = []
        for rule in SPAWN_RULES:
            if rule["when"] != kind:
                continue
            reason = rule["reason"]
            if detail:
                reason = f"{reason} ({detail})"
            created.append(
                self.spawn(
                    rule["tool"],
                    value,
                    reason=reason,
                    phase=rule["phase"],
                    priority=rule["priority"],
                    spawned_by=source or kind,
                )
            )
        return created

    def start(self, task_id: str) -> Task | None:
        task = self._tasks.get(task_id)
        if task is not None:
            task.state = TaskState.RUNNING
            task.started_at = datetime.now(UTC).isoformat()
        return task

    def complete(self, task_id: str, summary: str = "") -> Task | None:
        task = self._tasks.get(task_id)
        if task is not None:
            task.state = TaskState.DONE
            task.result_summary = summary
            task.finished_at = datetime.now(UTC).isoformat()
        return task

    def fail(self, task_id: str, error: str) -> Task | None:
        task = self._tasks.get(task_id)
        if task is not None:
            task.state = TaskState.FAILED
            task.error = error
            task.finished_at = datetime.now(UTC).isoformat()
        return task

    def block(self, task_id: str, reason: str) -> Task | None:
        """Mark a task blocked — out of scope, refused, or over budget."""
        task = self._tasks.get(task_id)
        if task is not None:
            task.state = TaskState.BLOCKED
            task.error = reason
        return task

    def skip(self, task_id: str, reason: str) -> Task | None:
        task = self._tasks.get(task_id)
        if task is not None:
            task.state = TaskState.SKIPPED
            task.result_summary = reason
            task.finished_at = datetime.now(UTC).isoformat()
        return task

    # -- queries ------------------------------------------------------------ #

    def get(self, task_id: str) -> Task | None:
        return self._tasks.get(task_id)

    def all(self) -> list[Task]:
        return list(self._tasks.values())

    def by_state(self, state: TaskState) -> list[Task]:
        return [t for t in self._tasks.values() if t.state is state]

    def ready(self, *, limit: int = 20) -> list[Task]:
        """Pending tasks whose dependencies are all satisfied, highest priority first."""
        out = []
        for task in self._tasks.values():
            if task.state is not TaskState.PENDING:
                continue
            unmet = [
                dep for dep in task.depends_on
                if (self._tasks.get(dep) is None or self._tasks[dep].state is not TaskState.DONE)
            ]
            if unmet:
                continue
            out.append(task)
        return sorted(out, key=lambda t: (-t.priority, t.created_at))[:limit]

    def next_task(self) -> Task | None:
        ready = self.ready(limit=1)
        return ready[0] if ready else None

    def stats(self) -> dict[str, Any]:
        by_state: dict[str, int] = {}
        by_phase: dict[str, int] = {}
        for task in self._tasks.values():
            by_state[task.state.value] = by_state.get(task.state.value, 0) + 1
            by_phase[task.phase] = by_phase.get(task.phase, 0) + 1
        return {
            "total": len(self._tasks),
            "by_state": by_state,
            "by_phase": by_phase,
            "ready": len(self.ready(limit=1000)),
        }

    # -- rendering ---------------------------------------------------------- #

    def to_mermaid(self, *, max_nodes: int = 60) -> str:
        """Mermaid flowchart for the report. Shows how discoveries drove the work."""
        symbols = {
            TaskState.DONE: "✓", TaskState.RUNNING: "▶", TaskState.PENDING: "…",
            TaskState.BLOCKED: "⊘", TaskState.FAILED: "✗", TaskState.SKIPPED: "–",
        }
        lines = ["flowchart TD"]
        tasks = sorted(self._tasks.values(), key=lambda t: t.created_at)[:max_nodes]
        aliases = {task.id: f"T{index}" for index, task in enumerate(tasks)}
        for task in tasks:
            label = f"{symbols[task.state]} {task.tool}<br/>{task.target[:40]}"
            lines.append(f'    {aliases[task.id]}["{label}"]')
        for task in tasks:
            for dep in task.depends_on:
                if dep in aliases:
                    lines.append(f"    {aliases[dep]} --> {aliases[task.id]}")
            if task.spawned_by:
                for other in tasks:
                    if other.tool == task.spawned_by and other.id != task.id:
                        lines.append(f"    {aliases[other.id]} -.spawned.-> {aliases[task.id]}")
                        break
        if len(self._tasks) > max_nodes:
            lines.append(f'    more["… {len(self._tasks) - max_nodes} more tasks"]')
        return "\n".join(lines)

    # -- persistence -------------------------------------------------------- #

    def save(self, path: Path | None = None) -> Path:
        target = Path(path or self.path or "taskgraph.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(
                {
                    "generated_at": datetime.now(UTC).isoformat(),
                    "stats": self.stats(),
                    "tasks": [t.to_dict() for t in self._tasks.values()],
                },
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        return target

    def load(self, path: Path) -> int:
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return 0
        loaded = 0
        known = set(Task.__dataclass_fields__)
        for record in payload.get("tasks", []):
            try:
                self.add(Task(**{k: v for k, v in record.items() if k in known}))
                loaded += 1
            except (TypeError, ValueError):
                continue
        return loaded

    def __len__(self) -> int:
        return len(self._tasks)
