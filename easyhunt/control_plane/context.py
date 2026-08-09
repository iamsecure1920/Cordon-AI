"""Engagement context — the object every guarded call reaches through.

One :class:`Engagement` per run. It owns the scope artifact, the workspace on
disk, and the seven control-plane components. Tool modules never construct these
themselves; they call :func:`get_engagement`, which is how "there is no code path
that skips the control plane" stays true as the tool count grows.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from easyhunt.config import Config
from easyhunt.control_plane.approval import ApprovalGate, build_backend
from easyhunt.control_plane.audit import AuditLog
from easyhunt.control_plane.budget import Budget, BudgetLimits
from easyhunt.control_plane.jobs import JobManager
from easyhunt.control_plane.ratelimit import RateLimiter
from easyhunt.control_plane.sandbox import Sandbox, SandboxConfig
from easyhunt.control_plane.scope import Scope
from easyhunt.errors import ConfigError
from easyhunt.knowledge.findings import AssetStore, FindingStore
from easyhunt.knowledge.graphmemory import GraphMemory
from easyhunt.knowledge.memory import PoCMemory
from easyhunt.knowledge.taskgraph import TaskGraph

__all__ = ["Engagement", "get_engagement", "set_engagement"]

_SLUG = re.compile(r"[^a-z0-9._-]+")


def _slugify(text: str) -> str:
    return _SLUG.sub("-", text.strip().lower()).strip("-") or "engagement"


class Engagement:
    """A single authorized run: scope, workspace, guardrails, and knowledge."""

    def __init__(self, scope: Scope, config: Config, *, workspace: Path | None = None) -> None:
        self.scope = scope
        self.config = config
        self.started_at = datetime.now(UTC)

        self.workspace = Path(workspace) if workspace else self._default_workspace()
        self.workspace.mkdir(parents=True, exist_ok=True)
        for sub in ("raw", "evidence", "poc", "reports"):
            (self.workspace / sub).mkdir(exist_ok=True)

        self.audit = AuditLog(
            self.workspace / str(config.get("audit.file", "audit.jsonl")),
            hash_chain=bool(config.get("audit.hash_chain", True)),
            scope_fingerprint=scope.fingerprint(),
        )
        self.budget = Budget(
            BudgetLimits.from_dict(
                scope.budget, phase_tokens=config.get("llm.phase_token_budget") or {}
            ),
            path=self.workspace / "budget.json",
        )
        self.limiter = RateLimiter.from_scope(scope)
        approval_cfg = config.section("approval")
        self.approval = ApprovalGate(
            build_backend(approval_cfg),
            scope=scope,
            remember_ttl=float(approval_cfg.get("remember_ttl") or 0),
        )
        self.sandbox = Sandbox(
            SandboxConfig.from_dict(config.section("sandbox")),
            workspace=self.workspace,
            user_agent=scope.rules.user_agent,
        )

        # The scope carries the program's published list of ineligible
        # vulnerability classes; the store applies it as findings arrive, so
        # everything downstream agrees on what is reportable.
        self.findings = FindingStore(
            self.workspace / "findings.json", classifier=scope.excluded_finding
        )
        self.assets = AssetStore()
        # Resuming into an existing workspace inherits what earlier phases found.
        # The pipeline runs one process per phase, so without this every phase
        # starts blind and "chaining" means nothing.
        self.assets.load(self.workspace / "assets.json")

        # Authenticated sessions. 42 of 115 WSTG tests need one and had no way
        # to get one; the authorization tests need two at once. Loaded on resume
        # like assets, because the pipeline runs a process per phase.
        from easyhunt.knowledge.sessions import SessionStore

        self.sessions = SessionStore()
        self.sessions.load(self.workspace / "sessions.json")
        self.jobs = JobManager()
        # The agent's memory of what it meant to do next. Tools call
        # engagement.taskgraph.spawn(...) when a discovery implies follow-up work.
        self.taskgraph = TaskGraph(self.workspace / "taskgraph.json")
        # Cross-engagement PoC knowledge, kept outside the per-run workspace so it
        # survives to the next target. Holds methods, never credentials or data.
        memory_path = config.path("memory.poc_store", "~/.easyhunt/poc-memory.jsonl")
        self.memory = PoCMemory(memory_path or Path.home() / ".easyhunt" / "poc-memory.jsonl")
        # What this engagement knows and how it connects. Native by default;
        # mirrors into Neo4j when memory.graph_enabled is set.
        self.graph = GraphMemory(
            self.workspace / "graph-memory.json",
            neo4j_uri=(
                str(config.get("memory.graph_uri"))
                if config.get("memory.graph_enabled")
                else None
            ),
            neo4j_user=str(config.get("memory.graph_user", "neo4j")),
            neo4j_password=os.environ.get(
                str(config.get("memory.graph_password_env", "NEO4J_PASSWORD")), ""
            ),
            engagement=scope.name,
        )

        self.max_payload_bytes = int(config.get("workspace.max_payload_bytes", 262_144))
        self.warnings: list[str] = scope.validate()

        self.audit.record(
            "engagement_start",
            engagement=scope.name,
            authorization=scope.authorization,
            program_url=scope.engagement.get("program_url"),
            scope_source=scope.source,
            scope_fingerprint=scope.fingerprint(),
            scope_age_days=scope.age_days(),
            workspace=str(self.workspace),
            config_source=config.source,
            sandbox=self.sandbox.describe(),
            approval_backend=self.approval.backend.name,
            limits={
                "max_rps": scope.rules.max_rps,
                "max_concurrency": scope.rules.max_concurrency,
                **{k: v for k, v in vars(self.budget.limits).items() if k != "phase_token_budget"},
            },
            warnings=self.warnings,
        )

    # -- construction ------------------------------------------------------- #

    def _default_workspace(self) -> Path:
        root = self.config.path("workspace.root", "./engagements") or Path("./engagements")
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        return root / f"{_slugify(self.scope.name)}_{stamp}"

    @classmethod
    def create(
        cls,
        *,
        scope_path: str | Path | None = None,
        config_path: str | Path | None = None,
        workspace: str | Path | None = None,
    ) -> Engagement:
        from easyhunt.config import find_scope

        resolved_scope = find_scope(scope_path)
        if resolved_scope is None:
            raise ConfigError(
                "no scope.yaml found — EasyHunt refuses to run without an authorization "
                "artifact. Copy scope.example.yaml, fill it in from the program policy, "
                "and pass --scope or set $EASYHUNT_SCOPE."
            )
        scope = Scope.load(resolved_scope)
        config = Config.load(config_path)
        return cls(scope, config, workspace=Path(workspace) if workspace else None)

    # -- paths -------------------------------------------------------------- #

    @property
    def raw_dir(self) -> Path:
        return self.workspace / "raw"

    @property
    def evidence_dir(self) -> Path:
        return self.workspace / "evidence"

    @property
    def poc_dir(self) -> Path:
        return self.workspace / "poc"

    @property
    def reports_dir(self) -> Path:
        return self.workspace / "reports"

    def raw_path(self, tool: str, suffix: str = "jsonl") -> Path:
        stamp = datetime.now(UTC).strftime("%H%M%S%f")[:-3]
        return self.raw_dir / f"{_slugify(tool)}-{stamp}.{suffix}"

    # -- lifecycle ---------------------------------------------------------- #

    def discovered(self, kind: str, value: str, *, source: str = "", detail: str = "") -> list[Any]:
        """Tell the task graph about a discovery so it can enqueue follow-up work.

        Tools call this instead of touching the graph directly, which keeps the
        spawn rules in one place and means every spawned task carries a reason
        the report can quote.
        """
        tasks = self.taskgraph.on_discovery(kind, value, source=source, detail=detail)
        if tasks:
            self.audit.record(
                "tasks_spawned",
                discovery=kind,
                value=value,
                source=source,
                tasks=[{"id": t.id, "tool": t.tool, "reason": t.reason} for t in tasks],
            )
        return tasks

    def finish(self, *, outcome: str = "completed") -> dict[str, Any]:
        # Carry forward the methods that worked, so the next engagement starts
        # from what this one proved.
        remembered = 0
        for finding in self.findings.confirmed():
            if self.memory.remember_finding(finding, engagement_name=self.scope.name):
                remembered += 1

        summary = self.summary()
        summary["memory"] = {"techniques_remembered": remembered, **self.memory.stats()}
        # Index the engagement into graph memory before sealing it, so a later
        # session can ask what was learned without re-running recon.
        from easyhunt.knowledge.graphmemory import ingest_engagement

        indexed = ingest_engagement(self.graph, self)
        summary["graph_memory"] = {**self.graph.stats(), "indexed": indexed}
        self.graph.save()

        self.findings.save()
        self.assets.save(self.workspace / "assets.json")
        self.taskgraph.save()
        self.budget.persist()
        self.audit.record("engagement_end", outcome=outcome, summary=summary)
        return summary

    def summary(self) -> dict[str, Any]:
        return {
            "engagement": self.scope.name,
            "workspace": str(self.workspace),
            "started_at": self.started_at.isoformat(),
            "scope": self.scope.summary(),
            "assets": self.assets.counts(),
            "findings": self.findings.stats(),
            "budget": self.budget.cost_summary(),
            "rate_limit": self.limiter.stats(),
            "approvals": self.approval.stats(),
            "audit": {"path": str(self.audit.path), "chain_ok": self.audit.verify()[0]},
            "jobs": {"total": len(self.jobs.list()), "running": len(self.jobs.list(status="running"))},
            "taskgraph": self.taskgraph.stats(),
            "warnings": self.warnings,
        }


_CURRENT: Engagement | None = None


def set_engagement(engagement: Engagement | None) -> Engagement | None:
    global _CURRENT
    _CURRENT = engagement
    return _CURRENT


def get_engagement() -> Engagement:
    """Return the active engagement, or explain why there isn't one."""
    if _CURRENT is None:
        raise ConfigError(
            "no active engagement — load a scope first (easyhunt_load_scope, or "
            "start the MCP server with --scope)"
        )
    return _CURRENT


def current_engagement() -> Engagement | None:
    return _CURRENT
