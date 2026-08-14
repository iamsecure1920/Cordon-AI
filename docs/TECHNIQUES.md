# Technique Index

## 1. What this is

EasyHunt answers two different "what now" questions with two different sources:

| Question | Source | Answers |
|---|---|---|
| *What should I check?* | WSTG index (`wstg_lookup`) | 115 named tests by phase |
| *How do I check it?* | **Technique index** (`technique_lookup`) | per-bug-class techniques, bypass tables, payload shapes |

The technique index is built from
[`swisskyrepo/PayloadsAllTheThings`](https://github.com/swisskyrepo/PayloadsAllTheThings),
pinned at a specific commit. Each bug-class directory becomes one record that
names the **EasyHunt tools** that test the class, the **vetted payload lists**
that belong to it, and the **gf pattern packs** (`rules/gf/*.json`) that match
its sinks.

```bash
python3 scripts/fetch_pat.py --fetch     # clone at the pin, build the index
python3 scripts/fetch_pat.py --verify    # check the index against the pin
```

The index ships in `knowledge/pat/index.json` (MIT-licensed metadata, with
attribution on every record). It is rebuilt, not edited, by the script above.
It holds two kinds of record: `technique` (the 63 bug-class directories) and
`cheatsheet` (the 33 red-team files under "Methodology and Resources", most of
which are stubs whose bodies moved to `InternalAllTheThings` — the destination
URL is recorded in `moved_to` rather than a fabricated summary).

## 2. Why the payloads are not vendored

PAT's payload files are dense attack strings — RCE statements, reverse shells,
third-party callbacks. Firing them unvetted would violate the first invariant
(*"treat every third-party template and payload list as untrusted until vetted
and pinned"*). Two consequences:

* The index wires each technique to the payload lists the **vetted store**
  (`payloads/`, built by `scripts/vet_payloads.py`) already classified. It
  references list filenames, never ships the raw payload text.
* Classes whose payloads exist but have **no consumer tool** are still indexed —
  the technique is documented as methodology, and the gap (no validator accepts
  the list yet) is visible rather than implied away.

This is the same treatment the WSTG index gets, and for the same reason: content
someone else owns, pinned so it cannot change under us.

## 3. Querying it

`technique_lookup` is a passive, budget-exempt tool. Five ways in:

| Argument | What it returns |
|---|---|
| `class_name="sql-injection"` | one technique in full (tools, payloads, gf packs) |
| `tool="sqli_validate"` | every technique a tool covers |
| `technologies="Rails,MongoDB"` | techniques implied by the observed stack |
| `query="jwt forgery"` | free-text ranked search |
| `phase="input_validation"` | everything in one phase |

Retrieval, not automation: a record says which class a technique belongs to and
which tooling corresponds to it; whether it applies to *this* target is a
judgement no detector makes for you. Nothing here fires anything.

## 4. hunt_plan consults it automatically

`hunt_plan` (the planner) enriches every proposal with the matching technique:
its `category`/`title` are searched against the index and the best match's
wiring is copied onto the proposal, so a plan reads "test IDOR on the basket
order id with `authz_compare` using the `idor` gf pack" instead of stopping at
"try IDOR". Deterministic retrieval, no second LLM call; unmatched proposals are
left untouched.

## 5. Stack hints

`easyhunt/knowledge/techniques.py` carries a `STACK_HINTS` table mapping observed
technology to technique classes — the same shape as the WSTG index's stack
hints, so `http_probe`'s fingerprint can seed "what to try next" without walking
all 63 records.
