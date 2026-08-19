

class TestDuplicateCollapse:
    """One secret is one finding, however many bundles carry it.

    A bundler copies the same config into every chunk that imports it. Measured
    on a live engagement: 79 secrets findings, of which 56 were one
    ``AMPLITUDE_API_KEY`` in double quotes, 6 the same key in single quotes, and
    5 one ``private-key`` rule hitting the same JWK parser. Eight distinct
    values, seventy-nine rows.

    Severity is assigned per row, so a false positive duplicated fifty-six times
    outranks a real finding sitting alone — the queue stops expressing the
    ordering severity is for.
    """

    def _hit(self, rule, path, snippet, validated=False):
        return {"rule": rule, "path": path, "line": 1, "validated": validated,
                "validation_note": "", "snippet": snippet}

    def test_same_value_across_files_becomes_one_finding(self) -> None:
        from cordon.tools.secrets import _collapse_duplicates

        hits = [self._hit("generic-api-key", f"raw/chunk-{i}.js", 'KEY":"abc123"')
                for i in range(56)]
        out = _collapse_duplicates(hits)
        assert len(out) == 1, "56 copies of one key is one finding"
        assert len(out[0]["duplicate_paths"]) == 55, "the other 55 locations are kept"
        assert out[0]["path"] == "raw/chunk-0.js", "first location is the reported one"

    def test_every_other_location_is_retained_for_remediation(self) -> None:
        """Triage needs one row; remediation needs all the files."""
        from cordon.tools.secrets import _collapse_duplicates

        hits = [self._hit("aws", "a.js", "AKIA..."), self._hit("aws", "b.js", "AKIA...")]
        out = _collapse_duplicates(hits)
        assert out[0]["duplicate_paths"] == ["b.js:1"]

    def test_different_values_stay_separate(self) -> None:
        from cordon.tools.secrets import _collapse_duplicates

        out = _collapse_duplicates([
            self._hit("generic-api-key", "a.js", 'KEY":"aaa"'),
            self._hit("generic-api-key", "b.js", 'KEY":"bbb"'),
        ])
        assert len(out) == 2, "two distinct keys are two findings"

    def test_same_value_different_rule_stays_separate(self) -> None:
        from cordon.tools.secrets import _collapse_duplicates

        out = _collapse_duplicates([
            self._hit("aws", "a.js", "SECRET"),
            self._hit("private-key", "a.js", "SECRET"),
        ])
        assert len(out) == 2

    def test_a_validated_occurrence_wins_the_merge(self) -> None:
        """Validation is a property of the credential, not of the file."""
        from cordon.tools.secrets import _collapse_duplicates

        out = _collapse_duplicates([
            self._hit("aws", "a.js", "AKIA...", validated=False),
            self._hit("aws", "b.js", "AKIA...", validated=True),
        ])
        assert len(out) == 1
        assert out[0]["validated"] is True
        assert out[0]["path"] == "b.js", "the confirmed location is the one to report"

    def test_empty_input_is_safe(self) -> None:
        from cordon.tools.secrets import _collapse_duplicates

        assert _collapse_duplicates([]) == []
