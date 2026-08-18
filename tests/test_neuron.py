"""NeuronBrain — the associative experience memory.

The brain learns from validator outcomes (hit/clean/false-positive), remembers
false positives per (tool, rule, context), decays stale lessons, and ranks
techniques for a new target context. These tests pin the learning rules and
the recall/suppression semantics, not the internals.
"""

from __future__ import annotations

from easyhunt.knowledge.neuron import (
    BrainOutcome,
    NeuronBrain,
    context_signature,
)


class TestContextSignature:
    def test_order_independent(self) -> None:
        a = context_signature("sqli", technologies=["Next.js", "react"], waf_vendors=["cloudflare"])
        b = context_signature("sqli", technologies=["react", "Next.js"], waf_vendors=["Cloudflare"])
        assert a == b

    def test_class_is_first_segment(self) -> None:
        sig = context_signature("xss", technologies=["react"])
        assert sig.startswith("xss | react")

    def test_blank_inputs_are_safe(self) -> None:
        sig = context_signature("", technologies=["  ", ""], waf_vendors=[])
        assert sig == "unknown"


class TestLearning:
    def test_hit_strengthens_clean_weakens(self, tmp_path) -> None:
        brain = NeuronBrain(tmp_path / "brain.jsonl")
        brain.learn(vuln_class="sqli", technique="sqli_validate", outcome=BrainOutcome.HIT,
                    technologies=["next.js"], waf_vendors=["cloudflare"], engagement="e1")
        brain.learn(vuln_class="sqli", technique="sqli_validate", outcome=BrainOutcome.HIT,
                    technologies=["next.js"], waf_vendors=["cloudflare"], engagement="e1")
        brain.learn(vuln_class="sqli", technique="sqli_validate", outcome=BrainOutcome.CLEAN,
                    technologies=["next.js"], waf_vendors=["cloudflare"], engagement="e1")
        hits = brain.recall(vuln_class="sqli", technologies=["next.js"], waf_vendors=["cloudflare"])
        assert len(hits) == 1
        assert hits[0]["trials"] == 3
        assert hits[0]["hits"] == 2
        assert hits[0]["hit_ratio"] == round(2 / 3, 2)

    def test_false_positive_learns_lesson(self, tmp_path) -> None:
        brain = NeuronBrain(tmp_path / "brain.jsonl")
        for _ in range(2):
            brain.learn(vuln_class="ssrf", technique="testssl:ipv4_in_header",
                        outcome=BrainOutcome.FALSE_POSITIVE, technologies=["cloudflare"],
                        engagement="e1")
        verdict = brain.suppress(tool="testssl", rule="ipv4_in_header", vuln_class="ssrf",
                                 technologies=["cloudflare"])
        assert verdict["suppress"] is True
        assert verdict["total_fp"] == 2

    def test_single_fp_is_not_enough_to_suppress(self, tmp_path) -> None:
        brain = NeuronBrain(tmp_path / "brain.jsonl")
        brain.learn(vuln_class="ssrf", technique="testssl:ipv4_in_header",
                    outcome=BrainOutcome.FALSE_POSITIVE, technologies=["cloudflare"],
                    engagement="e1")
        assert brain.suppress(tool="testssl", rule="ipv4_in_header")["suppress"] is False

    def test_fp_lesson_is_context_specific(self, tmp_path) -> None:
        brain = NeuronBrain(tmp_path / "brain.jsonl")
        for _ in range(2):
            brain.learn(vuln_class="ssrf", technique="testssl:ipv4_in_header",
                        outcome=BrainOutcome.FALSE_POSITIVE, technologies=["cloudflare"],
                        engagement="e1")
        # Same tool+rule on a DIFFERENT stack: the lesson must not suppress it.
        verdict = brain.suppress(tool="testssl", rule="ipv4_in_header", vuln_class="ssrf",
                                 technologies=["nginx", "java"])
        assert verdict["suppress"] is False

    def test_unknown_outcome_is_refused(self, tmp_path) -> None:
        brain = NeuronBrain(tmp_path / "brain.jsonl")
        result = brain.learn(vuln_class="xss", technique="dalfox", outcome="maybe")
        assert result["ok"] is False
        assert len(brain) == 0


class TestRecall:
    def test_class_mismatch_recalls_nothing(self, tmp_path) -> None:
        brain = NeuronBrain(tmp_path / "brain.jsonl")
        brain.learn(vuln_class="sqli", technique="sqli_validate", outcome=BrainOutcome.HIT,
                    technologies=["react"], engagement="e1")
        assert brain.recall(vuln_class="xss", technologies=["react"]) == []

    def test_fuzzy_stack_transfer(self, tmp_path) -> None:
        """A lesson learned on next.js+react transfers to a next.js-only target."""
        brain = NeuronBrain(tmp_path / "brain.jsonl")
        brain.learn(vuln_class="ssti", technique="ssti_probe", outcome=BrainOutcome.HIT,
                    technologies=["next.js", "react", "cloudflare"], engagement="e1")
        hits = brain.recall(vuln_class="ssti", technologies=["next.js"])
        assert len(hits) == 1
        assert hits[0]["technique"] == "ssti_probe"

    def test_clean_heavy_technique_sinks_below_hit(self, tmp_path) -> None:
        brain = NeuronBrain(tmp_path / "brain.jsonl")
        brain.learn(vuln_class="xss", technique="dalfox", outcome=BrainOutcome.CLEAN,
                    technologies=["angular"], engagement="e1")
        brain.learn(vuln_class="xss", technique="web_injection_probe:xss",
                    outcome=BrainOutcome.HIT, technologies=["angular"], engagement="e1")
        hits = brain.recall(vuln_class="xss", technologies=["angular"])
        assert hits[0]["technique"] == "web_injection_probe:xss"

    def test_min_trials_filters_guesses(self, tmp_path) -> None:
        brain = NeuronBrain(tmp_path / "brain.jsonl")
        brain.learn(vuln_class="cmdi", technique="cmdi_probe", outcome=BrainOutcome.HIT,
                    technologies=["php"], engagement="e1")
        assert brain.recall(vuln_class="cmdi", technologies=["php"], min_trials=2) == []

    def test_confidence_label_tracks_trials(self, tmp_path) -> None:
        brain = NeuronBrain(tmp_path / "brain.jsonl")
        for _ in range(15):
            brain.learn(vuln_class="sqli", technique="sqli_validate", outcome=BrainOutcome.HIT,
                        technologies=["php"], engagement="e1")
        assert brain.recall(vuln_class="sqli", technologies=["php"])[0]["confidence"] == "strong"


class TestPersistence:
    def test_survives_a_restart(self, tmp_path) -> None:
        path = tmp_path / "brain.jsonl"
        brain = NeuronBrain(path)
        brain.learn(vuln_class="idor", technique="authz_compare", outcome=BrainOutcome.HIT,
                    technologies=["rails"], engagement="e1")
        brain.save()
        reloaded = NeuronBrain(path)
        hits = reloaded.recall(vuln_class="idor", technologies=["rails"])
        assert len(hits) == 1
        assert hits[0]["trials"] == 1

    def test_save_compacts_duplicates(self, tmp_path) -> None:
        path = tmp_path / "brain.jsonl"
        brain = NeuronBrain(path)
        for _ in range(3):
            brain.learn(vuln_class="sqli", technique="sqli_validate", outcome=BrainOutcome.HIT,
                        technologies=["php"], engagement="e1")
        brain.save()
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        assert len(lines) == 1  # one synapse, not three appends
        reloaded = NeuronBrain(path)
        assert reloaded.recall(vuln_class="sqli", technologies=["php"])[0]["trials"] == 3

    def test_stats_reports_learning(self, tmp_path) -> None:
        brain = NeuronBrain(tmp_path / "brain.jsonl")
        brain.learn(vuln_class="sqli", technique="sqli_validate", outcome=BrainOutcome.HIT,
                    technologies=["php"], engagement="e1")
        brain.learn(vuln_class="xss", technique="dalfox", outcome=BrainOutcome.CLEAN,
                    technologies=["react"], engagement="e1")
        stats = brain.stats()
        assert stats["synapses"] == 2
        assert stats["by_technique"]["sqli_validate"] == 1


class TestSensing:
    """The brain's live activity feed: sense(), state(), history()."""

    def test_sense_ingests_tool_calls(self, tmp_path) -> None:
        brain = NeuronBrain(tmp_path / "brain.jsonl", tmp_path / "activity.jsonl")
        brain.sense({"event": "tool_call", "phase": "scan", "tool": "nuclei_scan",
                     "mode": "active", "outcome": "ok", "findings": 3,
                     "targets": ["a.example.com"], "duration_ms": 1200})
        state = brain.state()
        assert state["current"]["phase"] == "scan"
        assert state["current"]["tool"] == "nuclei_scan"
        assert state["recent"][0]["findings"] == 3

    def test_sense_ignores_bookkeeping(self, tmp_path) -> None:
        brain = NeuronBrain(tmp_path / "brain.jsonl", tmp_path / "activity.jsonl")
        brain.sense({"event": "engagement_start", "engagement": "x"})
        brain.sense({"event": "some_other_event", "phase": "scan"})
        assert brain.state()["activity_count"] == 1

    def test_sense_never_raises_on_bad_input(self, tmp_path) -> None:
        brain = NeuronBrain(tmp_path / "brain.jsonl", tmp_path / "activity.jsonl")
        brain.sense({})  # no event key
        brain.sense({"event": "tool_call"})  # no other fields
        assert brain.state()["activity_count"] == 1

    def test_engagement_end_returns_to_idle(self, tmp_path) -> None:
        brain = NeuronBrain(tmp_path / "brain.jsonl", tmp_path / "activity.jsonl")
        brain.sense({"event": "tool_call", "phase": "exploit", "tool": "sqli_validate",
                     "outcome": "ok", "findings": 0})
        brain.sense({"event": "engagement_end", "engagement": "x"})
        assert brain.state()["current"]["phase"] == "idle"

    def test_history_filters_by_tool_and_phase(self, tmp_path) -> None:
        brain = NeuronBrain(tmp_path / "brain.jsonl", tmp_path / "activity.jsonl")
        brain.sense({"event": "tool_call", "phase": "scan", "tool": "nuclei_scan",
                     "outcome": "ok", "findings": 1})
        brain.sense({"event": "tool_call", "phase": "exploit", "tool": "sqli_validate",
                     "outcome": "ok", "findings": 0})
        brain.sense({"event": "tool_call", "phase": "scan", "tool": "nuclei_scan",
                     "outcome": "error", "error_code": "refused", "findings": 0})
        assert len(brain.history(tool="sqli_validate")) == 1
        assert len(brain.history(phase="scan")) == 2
        assert len(brain.history(outcome="error")) == 1
        assert brain.history(tool="nuclei_scan")[0]["findings"] == 1

    def test_history_survives_restart(self, tmp_path) -> None:
        activity = tmp_path / "activity.jsonl"
        brain = NeuronBrain(tmp_path / "brain.jsonl", activity)
        brain.sense({"event": "tool_call", "phase": "probe", "tool": "http_probe",
                     "outcome": "ok", "findings": 0})
        reloaded = NeuronBrain(tmp_path / "brain.jsonl", activity)
        assert len(reloaded.history(phase="probe")) == 1

    def test_audit_observer_wires_sensing(self, tmp_path) -> None:
        """The audit log's observer hook feeds the brain every tool call."""
        from easyhunt.control_plane.audit import AuditLog

        brain = NeuronBrain(tmp_path / "brain.jsonl", tmp_path / "activity.jsonl")
        log = AuditLog(tmp_path / "audit.jsonl")
        log.observe(brain.sense)
        log.tool_call(tool="http_probe", phase="probe", mode="active", targets=["a.example.com"])
        log.tool_call(tool="nuclei_scan", phase="scan", mode="active", targets=["a.example.com"],
                      outcome="error", error="scope denied")
        state = brain.state()
        assert state["activity_count"] == 2
        assert len(brain.history(tool="nuclei_scan")) == 1
        assert brain.history(tool="nuclei_scan")[0]["outcome"] == "error"

    def test_observer_failure_does_not_break_audit(self, tmp_path) -> None:
        from easyhunt.control_plane.audit import AuditLog

        def boom(record):
            raise RuntimeError("observer crashed")

        log = AuditLog(tmp_path / "audit.jsonl")
        log.observe(boom)
        entry = log.tool_call(tool="http_probe", phase="probe", mode="active", targets=["a"])
        assert entry["event"] == "tool_call"  # audit still wrote its line


class TestBrainWatchCanonicalization:
    """The animation must map audit phase slugs to pipeline labels.

    The audit layer records tool-owner phase names (recon_passive, js_analysis,
    http_probe, vuln_scan); the animation draws canonical pipelines (recon, js,
    probe, scan). Without the mapping, real runs never light a pulse.
    """

    def test_canonical_phase_maps_audit_slugs(self) -> None:
        from easyhunt.tools.brain_watch import _canonical_phase

        assert _canonical_phase("http_probe") == "probe"
        assert _canonical_phase("recon_passive") == "recon"
        assert _canonical_phase("js_analysis") == "js"
        assert _canonical_phase("vuln_scan") == "scan"
        # Already-canonical names pass through untouched.
        assert _canonical_phase("exploit") == "exploit"
        assert _canonical_phase("tls") == "tls"

    def test_pulse_events_key_on_canonical_phases(self) -> None:
        from easyhunt.tools.brain_watch import _pulse_events

        events = [
            {"phase": "http_probe", "tool": "cors_audit", "findings": 1},
            {"phase": "exploit", "tool": "sqli_validate", "findings": 0},
        ]
        latest = _pulse_events(events)
        assert "probe" in latest  # not "http_probe"
        assert latest["probe"]["tool"] == "cors_audit"
        assert "exploit" in latest
