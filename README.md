# claim-diode: every sentence carries its evidence digest

Proves: each claim in a generated compliance report is bound to a hashed evidence artifact, and one changed byte lists every claim that cites it as INVALIDATED. Verify in 60s: `python3 claimdiode.py demo`.

`claimdiode.py` (python 3.9 stdlib, no network) binds each claim in a generated report to the hashed evidence behind it. Three properties:

- A claim cannot be rendered without an evidence id.
- A claim's confidence cannot exceed its weakest link. An INFERRED crosswalk edge, INFERRED provenance or stale evidence caps it at LOW.
- When an evidence artifact changes, every claim that cites it is listed as INVALIDATED, with its report and section, and `verify` exits 1.

2-minute demo (synthetic system, runs in a temp dir, touches nothing):

```
python3 claimdiode.py demo
python3 claimdiode.py --selftest      # last lines: claimdiode mutants killed K/K, claimdiode selftest N/N
```

Real output of `python3 claimdiode.py demo`:

```
demo: step 1 generate evidence, claims, reports and OSCAL for the synthetic acme-rag-assistant
chain: 7/7 links verify
checks: 5/5 rules PASS
confidence: 12/12 claims <= weakest link
oscal: 3/3 documents pass structural check
digests: 7/7 artifacts match claims
regen: 5/5 stages ok
demo: step 2 flip one byte in evidence/EV-MODEL.json (the model manifest copy, in a temp dir)
demo: step 3 verify
chain: 6/7 links verify
claims: 12/12 have evidence id
confidence: 12/12 claims <= weakest link
INVALIDATED CD-01 model-card/model-details: CHAIN_BROKEN EV-MODEL; DIGEST_MISMATCH EV-MODEL
INVALIDATED CD-02 model-card/security-considerations: CHAIN_BROKEN EV-MODEL; DIGEST_MISMATCH EV-MODEL
INVALIDATED CD-03 model-card/metrics: CHAIN_BROKEN EV-MODEL; DIGEST_MISMATCH EV-MODEL
INVALIDATED CD-04 ai-rmf-profile/measure: CHAIN_BROKEN EV-MODEL; DIGEST_MISMATCH EV-MODEL
INVALIDATED CD-05 ai-rmf-profile/measure: CHAIN_BROKEN EV-MODEL; DIGEST_MISMATCH EV-MODEL
INVALIDATED CD-06 eu-ai-annex-iv/point-3-monitoring-and-control: CHAIN_BROKEN EV-MODEL; DIGEST_MISMATCH EV-MODEL
INVALIDATED CD-07 eu-ai-annex-iv/point-1-general-description: CHAIN_BROKEN EV-MODEL; DIGEST_MISMATCH EV-MODEL
claimdiode: 7 of 12 claims INVALIDATED
digests: 6/7 artifacts match claims
demo: step 4 regenerate from the source inputs
chain: 7/7 links verify
checks: 5/5 rules PASS
confidence: 12/12 claims <= weakest link
oscal: 3/3 documents pass structural check
digests: 7/7 artifacts match claims
regen: 5/5 stages ok
demo: after tamper: 7 of 12 claims INVALIDATED, verify exit 1
demo: after regen: 0 of 12 claims INVALIDATED, verify exit 0
demo: 2/2 expectations met
```

Commands: `collect` (evidence JSON plus a `manifest.jsonl` hash chain, link = sha256(prev + canonical json)), `check` (5 policy-as-code rules in `rules/`), `report`, `oscal`, `verify`, `teeth` (each rule must go RED on its fixture in `mutants/`), `regen`, `demo`. Each prints its oracle line last, for example `chain: N/N links verify`, `digests: N/N artifacts match claims`, `claims: N/N have evidence id`, `confidence: N/N claims <= weakest link`, `teeth: N/N controls RED on mutant`, `oscal: N/N documents pass structural check`. Checked-in output lives in `examples/claimdiode-out/` (rebuilt using `--now 2026-11-02T00:00:00Z`).

Prior art, credited plainly: hashed evidence, OSCAL output and CI gates already exist in [Mihirajmera/llm-redteam-evidence](https://github.com/Mihirajmera/llm-redteam-evidence) and [VibeTensor/attestix](https://github.com/VibeTensor/attestix). The new part here is claim-level binding, confidence propagation through the crosswalk, and automatic invalidation. Not found in a GitHub search on 2026-11-02; that is a search result, not a claim of being first.

What this is not: it makes no compliance, certification or readiness claim. The OSCAL files are checked structurally only (required keys, uuid and date-time shape, reference integrity, known control ids), and their structure follows the 1.1.x model shape. Authoritative validation is the official [oscal-cli](https://github.com/metaschema-framework/oscal-cli), which is optional and not run here. The model, evidence and tests are synthetic: a deterministic mock model with an injectable flaw.

CI: `.github/workflows/ci.yml` runs `pytest`, both selftests, the demo, regenerates the outputs and runs `git diff --exit-code` on them. It runs when this folder is its own repo (GitHub only reads `.github/` at a repository root).

---

# grc-autofill

**Fill the mechanical 90% of a GRC report from evidence files, and leave the judgment 10% visibly empty.** One Python file, standard library only, no network, no API keys, no model calls. Runs on Python 3.9+.

```
git clone <this-repo> && cd grc-autofill
python3 grc_autofill.py --evidence examples/evidence --all --out out --date 2026-11-02
python3 grc_autofill.py --selftest      # exit 0 iff the tool can actually fail
```

Expected last lines (identical on any machine, because it is deterministic):

```
grc-autofill: ssp AUTO 11/11 fields filled, JUDGMENT 8 left
grc-autofill: AUTO 59/61 fields filled, JUDGMENT 51 left
```

The generated reports for the demo system are checked in under `examples/out/`, so you can read the result without running anything.

## The problem

A System Security Plan, an assessment report, a POA&M, a model card: most of each document is the same facts, retyped. Control tables, risk tables, policy lists, counts, exception ageing. Retyping drifts, and a tool that fills the blanks with plausible text is worse than no tool, because a made-up sentence looks identical to a real one.

## The contract

Templates carry two kinds of placeholder:

| Syntax | Meaning | What the tool does |
|---|---|---|
| `{{NAME}}` | AUTO field, resolved from evidence files | Fills it, or leaves `{{NAME}}` in place and counts it as unfilled |
| `{{J.NAME}}` | JUDGMENT field (boundary, narrative, risk acceptance, sign-off) | Never fills it. Counted as "left" |

Rules the tool enforces, each proven by a planted-defect case in `--selftest`:

- **Missing evidence stays visible.** No file, empty file, header-only table: the placeholder survives and the AUTO count drops. Nothing is blank-filled.
- **Malformed evidence is caught.** A TSV with a missing required column or a ragged row is treated as missing, named on stdout, and the run exits 1.
- **Unknown placeholders are flagged.** A typo like `{{CONTROL_CONT}}` is counted and left, never silently dropped.
- **Judgment is never filled**, even when evidence with a matching name exists.
- **Controls without proof are flagged.** In the control table, a control with no evidence path shows `NO-EVIDENCE`; one pointing at a file that does not exist shows `EVIDENCE-FILE-MISSING`.

The final stdout line is always `grc-autofill: AUTO a/b fields filled, JUDGMENT n left`. A run over the demo evidence deliberately omits `AUDIT.md`, so you can see two unfilled fields (`59/61`) instead of a suspicious perfect score.

## Evidence files

Passed with `--evidence DIR`. File names are fixed; every file is optional, and a missing one only costs you the fields that need it.

| File | Read for |
|---|---|
| `CONTROLS.tsv` | control table, oracle list, SOC 2 / Annex A / CSF matrices |
| `RISK-REGISTER.tsv` | risk table, POA&M items (rows whose `open_gap` starts with `yes`) |
| `POLICIES.md` | `Scope:` line and `## P<n>` policy headings |
| `EVIDENCE-INDEX.md` | control / command / receipt table |
| `GUARDS.tsv` | automated-check stats, failing checks, framework tags |
| `AUDIT.md` | audit excerpt (first 15 non-blank lines) |
| `EXCEPTIONS.tsv` | exception counts and ageing table |
| `COVERAGE.md` | OWASP LLM Top 10 coverage table |

`examples/evidence/` is a **synthetic** demo system (`acme-rag-assistant`). Every row in it is invented for this repo.

## Fan-out by data, not code

Reports are not listed anywhere in the code. The tool lists the files in `templates/` and each one is a report.

**Add a report:** drop `templates/my-report.md` in. Use `{{NAME}}` for any AUTO field already known to the tool and `{{J.NAME}}` for judgment. Start every `## section` with an `AUTO:` or `JUDGMENT:` line saying where it comes from. `--all` and `--selftest` pick it up with no code edit. (`--selftest` checks this: it drops a template into a scratch copy and asserts it becomes a report.)

**Add a standard:** add a row to `STANDARDS.tsv` (`standard`, `artifact`, `section_id`, `section_title`, `required_fields`, `source_url`, `fetched`). Set `fetched` to `yes` only where the text was actually read; otherwise use `structure-only`. The selftest fails if an `artifact` named there has no template.

**Map a control to a framework:** add a row to `CROSSWALK.tsv`. Leave a column blank unless a source grounds it, and say how in `basis`.

The only code edit is a brand-new AUTO field *type* (a new resolver in the `RES` table), which is a deliberate step.

## Files

```
grc_autofill.py      the tool and its selftest
templates/           8 report templates (SSP, SAP/SAR, POA&M, AI RMF profile, CSF 2.0 profile,
                     EU AI Act Annex IV, SOC 2 style controls report, model card)
STANDARDS.tsv        report structure per standard, with source_url and a fetched flag
CROSSWALK.tsv        control to framework mapping, with source and basis (provenance) columns
examples/evidence/   synthetic demo inputs
examples/out/        generated output for the demo (selftest asserts it matches a fresh run)
claimdiode.py        claim-diode tool and its selftest
examples/model_manifest.json, examples/claims.tsv, rules/, mutants/
                     claim-diode inputs, policy-as-code rules and their mutant fixtures
examples/claimdiode-out/  claim-diode generated output (selftest asserts it matches a fresh run)
.github/workflows/ci.yml    CI gate
tests/               pytest wrapper around both selftests and the demo
LICENSE              MIT
```

## Teeth, not theater

`python3 grc_autofill.py --selftest` runs 25 checks and exits non-zero if any fails. A third of them are planted defects that the tool must catch: evidence deleted, a short TSV row, a required column removed, an unknown placeholder, a judgment field whose name matches real evidence. It also asserts the template set is non-empty, so "zero templates, zero problems" cannot pass.

```
PASS PLANTED missing evidence file: placeholder kept and counted
PASS PLANTED malformed TSV (short row): caught, field left unfilled
...
grc-autofill selftest 25/25
```

## Honesty Statement

Every number in this README is the printed last line of a command in this repo, and `pytest` re-runs those commands. The demo system, its evidence and its model are synthetic. The novelty claim for claim-diode is a search result from one date, not a claim of being first.

## Limitations

- **Not legal advice, and not an attestation.** The output is a draft for a human assessor. Assessor review is required before any of it is relied on.
- **EU AI Act Annex IV text** in `STANDARDS.tsv` came from a **non-primary mirror**. Verify against the primary text before use. Risk classification of a system is a decision for the owner and counsel.
- **ISO/IEC 42001 and ISO/IEC 27001**: clause ids, structure only. The standards' text is not public and was not fetched; the tool uses clause and Annex A identifiers, nothing more.
- **AICPA SOC 2**: Trust Services Criteria ids and short criterion names only. The criteria text is AICPA copyrighted and is not reproduced or fetched.
- **EU AI Act Annex IV primary source**: Regulation (EU) 2024/1689 on EUR-Lex (`https://eur-lex.europa.eu/eli/reg/2024/1689/oj`). The EUR-Lex fetch on 2026-11-02 returned no text, so the Annex IV rows stay on the mirror and carry a `FETCH-FAILED` marker in `STANDARDS.tsv`; `tests/test_standards.py` fails if a mirror row loses that marker.
- **OWASP LLM mappings in `CROSSWALK.tsv` are INFERRED** from title matches, not from any authoritative mapping. The `basis` column says so on every such row. Verify before relying on them.
- Several CSF 2.0, AI RMF and Annex IV rows are structure only, as flagged in the `fetched` and `required_fields` columns of `STANDARDS.tsv`.
- The demo content is synthetic. It demonstrates the mechanism and says nothing about any real system.

## Trace matrix, blueprint and escalation

`TRACE-MATRIX.tsv` maps 38 real functions in `grc_autofill.py` and `claimdiode.py` to control ids (SOC 2 TSC 2017, EU AI Act articles, ISO/IEC 42001 clauses, NIST AI RMF subcategories), each row naming the selftest case that enforces it. A row is GROUNDED only where the requirement text was quoted from a fetched public page (EU AI Act Art. 9 to 15, from a non-primary mirror). Every other row is an INFERRED paraphrase, flagged as such.

```
python3 trace.py check        # last line: trace: 38/38 rows verify
python3 trace.py --selftest   # last line: trace selftest 19/19
python3 trace.py render       # writes TRACE-MATRIX.md
python3 trace.py escalate --findings examples/findings.json --out examples/escalate-out   # last line: escalate: 3 issues from 7 findings
```

`ESCALATION.tsv` holds the escalation rules as data, and `escalate` writes Jira-shaped JSON offline and sends nothing. `docs/BLUEPRINT.md` is the engineering manual and lists its gaps, including that role-based access control is NOT IMPLEMENTED. `templates/ml-pipeline-audit.md` is a new four-section report template. None of this is a compliance claim.

