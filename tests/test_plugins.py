"""Plugin/rule layer: a YAML drop-in adds a detection, a broken one is rejected."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from cordon.errors import PluginError
from cordon.plugins.loader import PluginRegistry, load_all
from cordon.plugins.matchers import MatchInput, evaluate_rule
from cordon.plugins.schema import validate_manifest

REPO_RULES = Path(__file__).resolve().parents[1] / "rules"


def rule_pack(**overrides) -> dict:
    base = {
        "id": "test-rule",
        "kind": "rule-pack",
        "phase": "vuln_scan",
        "mode": "passive",
        "severity": "medium",
        "description": "A test rule that detects a marker in a response body.",
        "matchers": [{"type": "word", "part": "body", "words": ["MARKER"]}],
        "verify": {"manual": True, "note": "Refetch the URL and confirm by hand."},
    }
    base.update(overrides)
    return base


class TestManifestValidation:
    def test_valid_manifest_loads(self) -> None:
        manifest = validate_manifest(rule_pack())
        assert manifest.id == "test-rule" and manifest.severity == "medium"

    def test_verify_block_is_mandatory(self) -> None:
        data = rule_pack()
        del data["verify"]
        with pytest.raises(PluginError, match="no PoC, no finding"):
            validate_manifest(data)

    def test_manual_verify_needs_a_note(self) -> None:
        with pytest.raises(PluginError, match="verify.note"):
            validate_manifest(rule_pack(verify={"manual": True}))

    def test_automated_verify_needs_a_command(self) -> None:
        with pytest.raises(PluginError, match="verify.command"):
            validate_manifest(rule_pack(verify={"manual": False, "note": "x"}))

    @pytest.mark.parametrize(
        ("field", "value", "match"),
        [
            ("kind", "wat", "unknown kind"),
            ("phase", "wat", "unknown phase"),
            ("mode", "wat", "mode must be"),
            ("severity", "apocalyptic", "severity must be"),
            ("id", "X", "'id' must be"),
            ("description", "short", "description"),
        ],
    )
    def test_bad_fields_are_rejected_with_a_clear_message(self, field, value, match) -> None:
        with pytest.raises(PluginError, match=match):
            validate_manifest(rule_pack(**{field: value}))

    def test_typo_in_a_key_is_an_error_not_a_silent_default(self) -> None:
        # 'severty' would otherwise silently leave severity at 'info'.
        with pytest.raises(PluginError, match="unknown manifest key"):
            validate_manifest(rule_pack(severty="critical"))

    def test_rule_pack_needs_a_matcher(self) -> None:
        with pytest.raises(PluginError, match="at least one matcher"):
            validate_manifest(rule_pack(matchers=[]))

    def test_invalid_regex_in_a_matcher_is_caught_at_load(self) -> None:
        with pytest.raises(PluginError, match="invalid regex"):
            validate_manifest(
                rule_pack(matchers=[{"type": "regex", "regex": ["[unclosed"]}])
            )

    def test_unknown_matcher_type(self) -> None:
        with pytest.raises(PluginError, match="unknown matcher type"):
            validate_manifest(rule_pack(matchers=[{"type": "vibes", "words": ["x"]}]))


class TestModeMislabeling:
    def test_passive_plugin_using_aggressive_primitives_is_refused(self) -> None:
        manifest = {
            "id": "sneaky-plugin",
            "kind": "python-tool",
            "phase": "vuln_scan",
            "mode": "passive",
            "severity": "high",
            "description": "Claims to be passive while shelling out to sqlmap.",
            "entrypoint": "sneaky.py",
            "verify": {"manual": True, "note": "n/a"},
        }
        source = "import subprocess\nsubprocess.run(['sqlmap', '-u', url])\n"
        with pytest.raises(PluginError, match="aggressive primitives"):
            validate_manifest(manifest, source_text=source)

    def test_passive_plugin_with_clean_source_is_accepted(self) -> None:
        manifest = {
            "id": "clean-plugin",
            "kind": "python-tool",
            "phase": "recon",
            "mode": "passive",
            "severity": "info",
            "description": "Reads a well-known public path and parses it.",
            "entrypoint": "clean.py",
            "verify": {"manual": True, "note": "Confirm the contact address is live."},
        }
        source = "import httpx\nasync with httpx.AsyncClient() as c:\n    await c.get(url)\n"
        assert validate_manifest(manifest, source_text=source).mode == "passive"

    def test_python_tool_must_name_its_entrypoint(self) -> None:
        with pytest.raises(PluginError, match="entrypoint"):
            validate_manifest(
                rule_pack(kind="python-tool", matchers=None, phase="recon")
                | {"kind": "python-tool"}
            )


class TestMatcherEngine:
    def test_word_matcher(self) -> None:
        manifest = validate_manifest(rule_pack())
        assert evaluate_rule(manifest, MatchInput(body="xx MARKER yy")).matched
        assert not evaluate_rule(manifest, MatchInput(body="nothing here")).matched

    def test_and_condition_across_matchers(self) -> None:
        manifest = validate_manifest(
            rule_pack(
                condition="and",
                matchers=[
                    {"type": "status", "status": [200]},
                    {"type": "word", "words": ["MARKER"]},
                ],
            )
        )
        assert evaluate_rule(manifest, MatchInput(status=200, body="MARKER")).matched
        assert not evaluate_rule(manifest, MatchInput(status=404, body="MARKER")).matched

    def test_or_condition(self) -> None:
        manifest = validate_manifest(
            rule_pack(
                condition="or",
                matchers=[
                    {"type": "status", "status": [500]},
                    {"type": "word", "words": ["MARKER"]},
                ],
            )
        )
        assert evaluate_rule(manifest, MatchInput(status=200, body="MARKER")).matched

    def test_negative_matcher(self) -> None:
        manifest = validate_manifest(
            rule_pack(matchers=[{"type": "word", "part": "header", "words": ["text/html"], "negative": True}])
        )
        assert evaluate_rule(manifest, MatchInput(headers={"content-type": "application/json"})).matched
        assert not evaluate_rule(manifest, MatchInput(headers={"content-type": "text/html"})).matched

    def test_header_matcher(self) -> None:
        manifest = validate_manifest(
            rule_pack(matchers=[{"type": "header", "name": "server", "values": ["nginx"]}])
        )
        assert evaluate_rule(manifest, MatchInput(headers={"server": "nginx/1.24"})).matched

    def test_regex_extractor_pulls_groups(self) -> None:
        manifest = validate_manifest(
            rule_pack(
                extractors=[
                    {"name": "keys", "type": "regex", "group": 1, "regex": [r"(?m)^([A-Z_]+)="]}
                ]
            )
        )
        result = evaluate_rule(manifest, MatchInput(body="MARKER\nDB_PASSWORD=x\nAPI_KEY=y"))
        assert result.extracted["keys"] == ["DB_PASSWORD", "API_KEY"]

    def test_json_extractor(self) -> None:
        manifest = validate_manifest(
            rule_pack(
                matchers=[{"type": "word", "words": ["version"]}],
                extractors=[{"name": "v", "type": "json", "json": ["meta.version"]}],
            )
        )
        result = evaluate_rule(manifest, MatchInput(body='{"meta": {"version": "1.2.3"}}'))
        assert result.extracted["v"] == ["1.2.3"]

    def test_extractors_only_run_on_a_match(self) -> None:
        manifest = validate_manifest(
            rule_pack(extractors=[{"name": "k", "type": "regex", "regex": [r"\w+"]}])
        )
        assert evaluate_rule(manifest, MatchInput(body="no marker")).extracted == {}

    def test_scan_input_is_capped(self) -> None:
        manifest = validate_manifest(rule_pack())
        huge = "a" * (2 * 1024 * 1024) + "MARKER"
        # The marker sits past the cap, so it is deliberately not found: bounded
        # work beats a complete scan of an attacker-sized response.
        assert not evaluate_rule(manifest, MatchInput(body=huge)).matched


class TestDiscovery:
    def test_dropping_a_yaml_file_adds_a_detection(self, tmp_path: Path) -> None:
        rules = tmp_path / "rules" / "cordon"
        rules.mkdir(parents=True)
        (rules / "new-rule.yaml").write_text(yaml.safe_dump(rule_pack(id="brand-new")))
        registry = load_all([tmp_path / "rules"], import_python=False)
        assert registry.get("brand-new") is not None
        assert registry.evaluate({"body": "MARKER"})[0].rule_id == "brand-new"

    def test_a_broken_rule_is_rejected_without_disabling_the_good_ones(self, tmp_path: Path) -> None:
        rules = tmp_path / "rules" / "cordon"
        rules.mkdir(parents=True)
        (rules / "good.yaml").write_text(yaml.safe_dump(rule_pack(id="good-rule")))
        (rules / "bad.yaml").write_text(yaml.safe_dump(rule_pack(id="bad-rule", severity="nope")))
        registry = load_all([tmp_path / "rules"], import_python=False)
        assert registry.get("good-rule") is not None
        assert registry.get("bad-rule") is None
        assert "severity must be" in registry.report.rejected[0]["error"]

    def test_duplicate_ids_are_rejected(self, tmp_path: Path) -> None:
        rules = tmp_path / "rules" / "cordon"
        rules.mkdir(parents=True)
        (rules / "a.yaml").write_text(yaml.safe_dump(rule_pack(id="dupe")))
        (rules / "b.yaml").write_text(yaml.safe_dump(rule_pack(id="dupe")))
        registry = load_all([tmp_path / "rules"], import_python=False)
        assert any("duplicate id" in r["error"] for r in registry.report.rejected)

    def test_unparseable_yaml_is_reported_not_raised(self, tmp_path: Path) -> None:
        rules = tmp_path / "rules" / "cordon"
        rules.mkdir(parents=True)
        (rules / "broken.yaml").write_text("id: x\n  bad indent: [")
        registry = load_all([tmp_path / "rules"], import_python=False)
        assert registry.report.rejected

    def test_raw_engine_rules_are_tracked_by_directory(self, tmp_path: Path) -> None:
        nuclei_dir = tmp_path / "rules" / "nuclei"
        nuclei_dir.mkdir(parents=True)
        (nuclei_dir / "t.yaml").write_text(
            yaml.safe_dump({"id": "raw-template", "info": {"name": "x", "severity": "low"}})
        )
        registry = load_all([tmp_path / "rules"], import_python=False)
        assert len(registry.nuclei_paths()) == 1


class TestShippedRules:
    """The rules that ship with Cordon must themselves be valid."""

    def test_repo_rules_all_load(self) -> None:
        registry = PluginRegistry()
        registry.load_dir(REPO_RULES)
        assert registry.report.rejected == []
        assert {m.id for m in registry.rule_packs()} >= {
            "exposed-env-file",
            "dangling-cname-candidate",
        }

    def test_shipped_nuclei_template_is_discovered(self) -> None:
        registry = PluginRegistry()
        registry.load_dir(REPO_RULES)
        assert any("exposed-git-config" in p for p in registry.nuclei_paths())

    def test_shipped_bbot_preset_is_discovered(self) -> None:
        registry = PluginRegistry()
        registry.load_dir(REPO_RULES)
        assert registry.bbot_presets()

    def test_env_rule_fires_on_a_real_looking_response(self) -> None:
        registry = PluginRegistry()
        registry.load_dir(REPO_RULES)
        matches = registry.evaluate(
            {
                "url": "https://www.example.com/.env",
                "status": 200,
                "headers": {"content-type": "text/plain"},
                "body": "APP_ENV=production\nDB_PASSWORD=hunter2\nAWS_SECRET_ACCESS_KEY=abc\n",
            }
        )
        hit = next(m for m in matches if m.rule_id == "exposed-env-file")
        assert "DB_PASSWORD" in hit.extracted["env_keys"]

    def test_env_rule_does_not_fire_on_an_html_error_page(self) -> None:
        registry = PluginRegistry()
        registry.load_dir(REPO_RULES)
        matches = registry.evaluate(
            {
                "url": "https://www.example.com/.env",
                "status": 200,
                "headers": {"content-type": "text/html"},
                "body": "<html>DB_PASSWORD= not really</html>",
            }
        )
        assert not any(m.rule_id == "exposed-env-file" for m in matches)
