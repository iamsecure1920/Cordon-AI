"""AI triage, adversarial reconciliation, and the canary defense."""

from __future__ import annotations

import json
from typing import Any

import pytest
import yaml

from cordon.errors import ConfigError
from cordon.knowledge.findings import Finding, Severity, Status
from cordon.llm.triage import (
    Taskflow,
    TriageResult,
    _canary_penalty,
    _reconcile,
    run_taskflow,
    seed_canaries,
)

REPO_TASKFLOWS = __import__("pathlib").Path(__file__).resolve().parents[1] / "taskflows"


class ScriptedClient:
    """LLM stub whose reply depends on the step name in the prompt."""

    enabled = True

    def __init__(self, replies: dict[str, Any]) -> None:
        self.replies = replies
        self.calls: list[dict[str, Any]] = []

    async def complete(self, messages, *, tier="t1", phase="", purpose="", **kwargs):  # noqa: ANN001
        self.calls.append({"tier": tier, "purpose": purpose, "messages": messages})
        step = purpose.split(":")[-1].strip()
        payload = self.replies.get(step, [])
        if callable(payload):
            payload = payload(messages)

        class Response:
            text = json.dumps(payload)
            model = "stub/model"

            def json(self, default=None):  # noqa: ANN001
                return payload

        return Response()


def candidate(engagement, title: str, severity: Severity = Severity.MEDIUM) -> Finding:
    return engagement.findings.add(
        Finding(
            asset="https://www.example.com/x",
            title=title,
            severity=severity,
            status=Status.CANDIDATE,
            source_tool="nuclei",
            rule_id="test.rule",
        )
    )


class TestTaskflowLoading:
    def test_shipped_taskflow_loads(self) -> None:
        flow = Taskflow.load(REPO_TASKFLOWS / "default-triage.yaml")
        assert [s.name for s in flow.steps] == ["falsifier", "red-team", "severity-check"]
        assert flow.canaries == 3

    def test_confirm_verdict_is_refused(self, tmp_path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "name": "bad",
                    "steps": [{"name": "s", "allowed_verdicts": ["confirm", "keep"]}],
                }
            )
        )
        # A taskflow must not be able to grant itself confirmation authority.
        with pytest.raises(ConfigError, match="Only a reproducible PoC can confirm"):
            Taskflow.load(path)

    def test_steps_are_required(self, tmp_path) -> None:
        path = tmp_path / "empty.yaml"
        path.write_text(yaml.safe_dump({"name": "empty"}))
        with pytest.raises(ConfigError, match="needs a 'steps' list"):
            Taskflow.load(path)

    def test_step_filter_matches_by_severity_floor(self) -> None:
        flow = Taskflow.load(REPO_TASKFLOWS / "default-triage.yaml")
        severity_step = next(s for s in flow.steps if s.name == "severity-check")
        high = Finding(asset="a", title="t", severity=Severity.HIGH)
        low = Finding(asset="b", title="t", severity=Severity.LOW)
        assert severity_step.matches(high) and not severity_step.matches(low)


class TestCanaries:
    def test_canaries_use_a_non_resolvable_host(self) -> None:
        for canary in seed_canaries(5):
            assert ".invalid" in canary.asset
            assert canary.is_canary

    def test_canaries_are_unique(self) -> None:
        assets = [c.asset for c in seed_canaries(5)]
        assert len(set(assets)) == 5

    def test_catching_all_canaries_means_no_penalty(self) -> None:
        results = [TriageResult("c1", "drop", is_canary=True), TriageResult("c2", "drop", is_canary=True)]
        multiplier, report = _canary_penalty(results)
        assert multiplier == 1.0 and report["accuracy"] == 1.0

    def test_missing_every_canary_maximally_penalizes(self) -> None:
        results = [TriageResult("c1", "keep", is_canary=True), TriageResult("c2", "escalate", is_canary=True)]
        multiplier, report = _canary_penalty(results)
        assert multiplier == pytest.approx(0.4)
        assert report["canaries_missed"] == 2
        assert "reduced weight" in report["note"]

    def test_partial_accuracy_scales_the_penalty(self) -> None:
        results = [
            TriageResult("c1", "drop", is_canary=True),
            TriageResult("c2", "keep", is_canary=True),
        ]
        multiplier, _ = _canary_penalty(results)
        assert 0.4 < multiplier < 1.0

    def test_no_canaries_means_no_adjustment(self) -> None:
        multiplier, report = _canary_penalty([TriageResult("f1", "keep")])
        assert multiplier == 1.0 and report["canaries_seen"] == 0


class TestReconciliation:
    def test_agreement_is_taken_as_is(self) -> None:
        results = [
            TriageResult("f1", "drop", step="falsifier", confidence=0.9),
            TriageResult("f1", "drop", step="red-team", confidence=0.7),
        ]
        assert _reconcile(results)["f1"].verdict == "drop"

    def test_disagreement_escalates_rather_than_averaging(self) -> None:
        results = [
            TriageResult("f1", "drop", step="falsifier", reason="soft 404", confidence=0.9),
            TriageResult("f1", "keep", step="red-team", reason="looks real", confidence=0.8),
        ]
        decision = _reconcile(results)["f1"]
        assert decision.verdict == "escalate"
        assert "disagreed" in decision.reason

    def test_non_conflicting_verdicts_take_the_strongest(self) -> None:
        results = [
            TriageResult("f1", "keep", step="a", confidence=0.6),
            TriageResult("f1", "escalate", step="b", confidence=0.7),
        ]
        assert _reconcile(results)["f1"].verdict == "escalate"


class TestTriageRun:
    @pytest.fixture
    def flow(self) -> Taskflow:
        return Taskflow.from_dict(
            {
                "name": "test-flow",
                "canaries": 2,
                "steps": [
                    {"name": "falsifier", "tier": "t1", "allowed_verdicts": ["drop", "keep"]},
                    {"name": "red-team", "tier": "t1", "allowed_verdicts": ["drop", "keep", "escalate"]},
                ],
            },
            source="<test>",
        )

    async def test_unanimous_drop_removes_a_candidate(self, engagement, flow) -> None:
        noise = candidate(engagement, "Version banner disclosure")
        real = candidate(engagement, "Exposed .env", Severity.HIGH)

        def verdicts(messages: Any) -> list[dict[str, Any]]:
            data = json.loads(messages[-1]["content"].split("FINDINGS:\n")[1])
            out = []
            for item in data:
                if item["id"] == noise.id:
                    out.append({"id": item["id"], "verdict": "drop", "reason": "banner only", "confidence": 0.9})
                elif item["id"] == real.id:
                    out.append({"id": item["id"], "verdict": "keep", "reason": "real", "confidence": 0.8})
                else:  # canaries
                    out.append({"id": item["id"], "verdict": "drop", "reason": "host cannot exist", "confidence": 0.95})
            return out

        client = ScriptedClient({"falsifier": verdicts, "red-team": verdicts})
        result = await run_taskflow(client, flow, [noise, real], engagement=engagement)

        assert result["applied"]["dropped"] >= 1
        assert noise.status is Status.FALSE_POSITIVE
        assert real.status is Status.CANDIDATE

    async def test_a_lone_drop_never_discards_a_finding(self, engagement) -> None:
        # One pass says false positive, the other says it is real but unproven.
        # Automated triage must not resolve that by discarding evidence.
        flow = Taskflow.from_dict(
            {
                "name": "split",
                "canaries": 0,
                "steps": [
                    {"name": "falsifier", "allowed_verdicts": ["drop", "keep"]},
                    {"name": "red-team", "allowed_verdicts": ["keep", "escalate", "downgrade"]},
                ],
            },
            source="<test>",
        )
        finding = candidate(engagement, "Possible SSRF", Severity.HIGH)

        def falsify(messages: Any) -> list[dict[str, Any]]:
            data = json.loads(messages[-1]["content"].split("FINDINGS:\n")[1])
            return [{"id": i["id"], "verdict": "drop", "reason": "probably a redirect", "confidence": 0.8} for i in data]

        def defend(messages: Any) -> list[dict[str, Any]]:
            data = json.loads(messages[-1]["content"].split("FINDINGS:\n")[1])
            return [{"id": i["id"], "verdict": "escalate", "reason": "OOB probe would settle it", "confidence": 0.7} for i in data]

        client = ScriptedClient({"falsifier": falsify, "red-team": defend})
        result = await run_taskflow(client, flow, [finding], engagement=engagement)

        assert result["applied"]["dropped"] == 0
        assert result["applied"]["escalated"] == 1
        assert finding.status is not Status.FALSE_POSITIVE

    async def test_canaries_never_appear_in_the_findings_store(self, engagement, flow) -> None:
        real = candidate(engagement, "Exposed .env", Severity.HIGH)
        client = ScriptedClient({"falsifier": [], "red-team": []})
        await run_taskflow(client, flow, [real], engagement=engagement)
        assert engagement.findings.canaries() == []
        assert all(not f.is_canary for f in engagement.findings.all())

    async def test_triage_can_never_confirm(self, engagement, flow) -> None:
        real = candidate(engagement, "SQL injection", Severity.HIGH)

        def try_to_confirm(messages: Any) -> list[dict[str, Any]]:
            data = json.loads(messages[-1]["content"].split("FINDINGS:\n")[1])
            # The model tries to issue a verdict it was not granted.
            return [{"id": i["id"], "verdict": "confirm", "reason": "definitely real", "confidence": 1.0} for i in data]

        client = ScriptedClient({"falsifier": try_to_confirm, "red-team": try_to_confirm})
        await run_taskflow(client, flow, [real], engagement=engagement)

        assert real.status is not Status.CONFIRMED
        assert real.poc is None

    async def test_hallucinating_pass_has_its_confidence_reduced(self, engagement, flow) -> None:
        real = candidate(engagement, "Exposed admin panel", Severity.HIGH)

        def keep_everything(messages: Any) -> list[dict[str, Any]]:
            data = json.loads(messages[-1]["content"].split("FINDINGS:\n")[1])
            return [{"id": i["id"], "verdict": "keep", "reason": "verified", "confidence": 1.0} for i in data]

        client = ScriptedClient({"falsifier": keep_everything, "red-team": keep_everything})
        result = await run_taskflow(client, flow, [real], engagement=engagement)

        canary_check = result["steps"][0]["canary_check"]
        assert canary_check["canaries_missed"] == 2
        assert canary_check["confidence_multiplier"] < 1.0
        # A model claiming 1.0 confidence while confirming fabrications does not
        # get to keep that confidence.
        assert real.confidence < 1.0

    async def test_audit_records_the_triage_run(self, engagement, flow) -> None:
        real = candidate(engagement, "Exposed .env", Severity.HIGH)
        client = ScriptedClient({"falsifier": [], "red-team": []})
        await run_taskflow(client, flow, [real], engagement=engagement)
        runs = [r for r in engagement.audit.read_all() if r["event"] == "triage_run"]
        assert runs and runs[-1]["taskflow"] == "test-flow"

    async def test_empty_input_is_handled(self, engagement, flow) -> None:
        client = ScriptedClient({})
        result = await run_taskflow(client, flow, [], engagement=engagement)
        assert result["triaged"] == 0


class TestTriageTools:
    async def test_lists_shipped_taskflows(self, engagement) -> None:
        import cordon.tools.triage_tools  # noqa: F401
        from cordon.tools.base import REGISTRY

        engagement.config.data["triage"]["taskflows_dir"] = str(REPO_TASKFLOWS)
        result = await REGISTRY["triage_taskflows"].fn()
        assert any(f["name"] == "default-triage" for f in result["taskflows"])
        assert result["rejected"] == []

    async def test_triage_without_a_key_explains_itself(self, engagement, monkeypatch) -> None:
        import cordon.tools.triage_tools  # noqa: F401
        from cordon.tools.base import REGISTRY

        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        engagement.config.data["triage"]["taskflows_dir"] = str(REPO_TASKFLOWS)
        candidate(engagement, "Something", Severity.HIGH)
        result = await REGISTRY["triage_findings"].fn()
        assert result["ok"] is False and result["error"] == "llm_unavailable"

    async def test_canary_preview(self, engagement) -> None:
        import cordon.tools.triage_tools  # noqa: F401
        from cordon.tools.base import REGISTRY

        result = await REGISTRY["triage_canary_preview"].fn(count=2)
        assert len(result["canaries"]) == 2
        assert all(".invalid" in c["asset"] for c in result["canaries"])
