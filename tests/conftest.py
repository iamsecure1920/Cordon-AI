"""Shared fixtures. Every test runs against a throwaway workspace and a scope
built from ``example.com`` / TEST-NET ranges, so nothing here can touch a real host.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from easyhunt.config import Config
from easyhunt.control_plane.context import Engagement, set_engagement
from easyhunt.control_plane.scope import Scope


def scope_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "version": 1,
        "engagement": {
            "name": "test-engagement",
            "authorization": "owned",
            "fetched_at": datetime.now(UTC).isoformat(),
            "max_age_days": 7,
            "researcher_handle": "tester",
        },
        "in_scope": {
            "domains": ["example.com"],
            "wildcards": ["*.example.com"],
            "cidrs": ["203.0.113.0/24"],
            "ip_ranges": ["198.51.100.10-50"],
            "regex": [r"api-\d+\.example\.net"],
            "urls": ["https://app.example.org/v2/"],
        },
        "out_of_scope": {
            "domains": ["blog.example.com"],
            "wildcards": ["*.corp.example.com"],
            "cidrs": ["203.0.113.240/28"],
            "regex": [r".*\.staging\.example\.com"],
        },
        "rules": {
            "max_rps": 5,
            "max_concurrency": 3,
            "allow_aggressive": True,
            "allow_exploitation": True,
            "forbidden_paths": ["/admin/delete"],
        },
        "budget": {
            "llm_usd": 1.0,
            "wall_clock_minutes": 60,
            # Roomy enough that budget ceilings only fire in the tests that
            # deliberately exhaust them.
            "max_requests": 100_000,
            "max_tool_seconds": 600,
        },
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = {**base[key], **value}
        else:
            base[key] = value
    return base


@pytest.fixture
def scope() -> Scope:
    return Scope(scope_dict(), source="<test>")


@pytest.fixture
def scope_file(tmp_path: Path) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(yaml.safe_dump(scope_dict()), encoding="utf-8")
    return path


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        {
            "workspace": {"root": str(tmp_path / "engagements")},
            # Tests must never depend on a human being present.
            "approval": {"backend": "deny"},
            "sandbox": {"mode": "none"},
            # Keep cross-engagement memory out of the real home directory.
            "memory": {
                "poc_store": str(tmp_path / "poc-memory.jsonl"),
                "brain_store": str(tmp_path / "neuron-brain.jsonl"),
                "brain_activity": str(tmp_path / "brain-activity.jsonl"),
            },
        },
        source=str(tmp_path / "config.yaml"),
    )


@pytest.fixture
def engagement(scope: Scope, config: Config, tmp_path: Path):
    eng = Engagement(scope, config, workspace=tmp_path / "ws")
    set_engagement(eng)
    yield eng
    set_engagement(None)
