# grc-autofill and claim-diode: reports filled from evidence, every claim bound to a hash

Proves: the mechanical part of a GRC report is filled from evidence files, the judgment part is left visibly empty, each claim in a generated report is bound to a hashed evidence artifact, and one changed byte lists every claim that cites it as INVALIDATED. Verify in 60s: `python3 claimdiode.py demo`.

Two standard-library Python tools (3.9+, no network, no API keys, no model calls) live in this folder: `grc_autofill.py` fills report templates from evidence, and `claimdiode.py` binds each generated claim to the evidence behind it.

## The problem

An assessor's evidence has three failure modes. Evidence rot: the screenshot, export or spreadsheet that supported a statement in a System Security Plan was captured once, is not tied to the sentence it supports, and nobody can say whether it still describes the system. Manual screenshots: the same control table, risk table and policy list are retyped into every document, retyping drifts, and a screenshot cannot be recomputed or diffed. Control drift: the evidence changes after the report is signed, and the report keeps asserting the old state because nothing links the claim to the artifact. A tool that fills the blanks with plausible text makes this worse, because a made-up sentence looks identical to a real one.

Here a missing fact stays visibly missing, a judgment is never filled, and a claim whose evidence changed is listed as INVALIDATED instead of silently staying true.

## What this proves, and what it does not

Proves, each by a named case that `--selftest` runs:

- Missing, empty, header-only or malformed evidence leaves the placeholder in place and lowers the AUTO count. Nothing is blank-filled, and malformed evidence exits 1.
- A `{{J.NAME}}` judgment field is never filled, even when evidence with a matching name exists.
- A control with no evidence path shows `NO-EVIDENCE`, and one pointing at a missing file shows `EVIDENCE-FILE-MISSING`.
- A claim cannot be rendered without an evidence id, and its confidence cannot exceed its weakest link.
- Flipping one byte in an evidence artifact breaks the hash chain and lists every claim that cites it as INVALIDATED, with `verify` exiting 1.
- Each of the 5 policy rules can fail: `teeth` replays every rule against its fixture and requires RED, and `claimdiode.py --selftest` kills 12 of 12 mutants.

Does not prove (Limits):

- Compliance, certification or readiness for any framework or law. The output is a draft for a human assessor, not legal advice and not an attestation.
- That any real system is controlled. The demo system, its evidence and its model are synthetic: a deterministic mock model with an injectable flaw. The five probe families with three or four prompts each demonstrate the mechanism and are not an evaluation of any model.
- That evidence is true. The hash chain is tamper-evident inside one working directory. Someone who can rewrite the chain, the claims lock and the evidence together produces a consistent set. Anchoring the head link outside the directory is not implemented.
- Authoritative OSCAL validity. The OSCAL files are checked structurally only (required keys, uuid and date-time shape, reference integrity, known control ids). The official oscal-cli is optional and not run here.
- Access control. `rbac.py` is a deny-by-default policy check with separation of duties, but it authenticates nobody and the pipeline does not call it yet. Its audit log is a plain file, not tamper-evident.
- Retention and personal-data scanning of evidence directories. Both are listed as gaps in `docs/BLUEPRINT.md`.
- Sending anything. Escalation writes Jira-shaped JSON offline and sends nothing.

## The one command

```
git clone <this-repo> && cd grc-autofill
python3 claimdiode.py demo
```

The demo runs on the synthetic `acme-rag-assistant` in a temp dir and touches nothing in the repo. It generates evidence, claims, reports and OSCAL, flips one byte of the model manifest copy, verifies, then regenerates. Real output:

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

The report-filling tool has its own command:

```
python3 grc_autofill.py --evidence examples/evidence --all --out out --date 2026-11-02
python3 grc_autofill.py --selftest      # exit 0 iff the tool can actually fail
```

Real last lines of the first command (deterministic, identical on any machine because the date is passed in):

```
grc-autofill: ssp AUTO 11/11 fields filled, JUDGMENT 8 left
grc-autofill: AUTO 76/78 fields filled, JUDGMENT 56 left
```

Real last line of `--selftest`: `grc-autofill selftest 28/28`. The `76/78` is deliberate: the demo evidence omits `AUDIT.md`, so two fields stay unfilled (one each in the `eu-ai-annex-iv` and `sap-sar` reports) instead of showing a suspicious perfect score. The generated reports for the demo system are checked in under `examples/out/`, so you can read the result without running anything.

## Mapping

A mapping, not an attestation or audit opinion. Labels follow `TRACE-MATRIX.tsv`: GROUNDED means the requirement text was read from a fetched public page and a named selftest case enforces the mechanism; INFERRED means a short paraphrase that must be verified against the standard. Even a GROUNDED row maps by analogy: the hash-chained evidence log is an evidence log, not the event logging of a deployed high-risk system that Article 12 describes. The EU AI Act text came from a non-primary mirror because the EUR-Lex fetch returned no text, so verify against the Official Journal. ISO/IEC 42001 rows use clause ids only, since the standard is paywalled and was not read.

The matrix has 38 rows over 22 functions, 12 GROUNDED and 26 INFERRED, and `python3 trace.py check` fails if a named function, id or test disappears. It also carries SOC 2 TSC 2017 ids (for example CC4.1, CC8.1, PI1.1 to PI1.4), omitted from the table below to keep it readable. Rows marked docs only are not in the matrix, are enforced by no check, and are there to orient the reader.

| mechanism | function and enforcing case | EU AI Act | NIST AI RMF | ISO/IEC 42001 | NIST SP 800-53 rev5 | label |
|---|---|---|---|---|---|---|
| Hash-chained evidence log | `collect`, `chain_check`: "PLANTED break one hash-chain link" | Art. 12 | none | none | AU-9, SI-7 | Art. 12 GROUNDED; 800-53 INFERRED, docs only |
| Policy rules as data with a threshold per metric | `rule_status`: "each injected flaw turns exactly its own rule FAIL" | Art. 9 | none | none | none | GROUNDED |
| Rules must be able to fail | `teeth`: "PLANTED toothless rule (stays GREEN under its own mutant)" | none | none | 9.2 | CA-2 | 9.2 INFERRED; CA-2 INFERRED, docs only |
| Probe families against the mock model | `run_tests`, `check`, `eval_value`: "clean mock model passes all 5 rules" | Art. 15 | none | none | none | GROUNDED |
| Stale evidence capped LOW | `is_stale`: "PLANTED evidence older than max-age: STALE, capped LOW, verify fails" | none | MANAGE 4.1 | none | CA-7 | AI RMF INFERRED; CA-7 INFERRED, docs only |
| Security and resilience evaluation | `rule_status`: "PLANTED evidence older than max-age" | none | MEASURE 2.7 | none | none | INFERRED |
| Confidence computed, not authored | `bound`: "PLANTED upgrade an INFERRED-edge claim to HIGH" | none | none | 9.1 | none | INFERRED |
| Claim INVALIDATED when evidence changes | `verify`: "PLANTED flip one byte in the model manifest copy" | Art. 11 | none | 10.2 | CM-3 | Art. 11 GROUNDED; 10.2 INFERRED; CM-3 INFERRED, docs only |
| Report carries its own claim annotations | `report`, `fill_report`: "PLANTED strip a claim's annotation from the rendered report" | Art. 11, Annex IV | none | 7.5 | none | Art. 11 GROUNDED; Annex IV and 7.5 INFERRED |
| Malformed evidence rejected | `_read_tsv`: "PLANTED malformed TSV (short row): caught" | Art. 10 | none | none | none | GROUNDED |
| Control without evidence flagged | `_ev_check`: "control with no or missing evidence file is flagged" | Art. 13 | none | none | none | GROUNDED |
| Judgment fields never filled | `fill_text`: "PLANTED judgment field with matching evidence: never filled" | Art. 14 | GOVERN 3.2 | none | none | Art. 14 GROUNDED; GOVERN 3.2 INFERRED |
| POA&M lists only risks with an open gap | `_open_risks`: "POA&M table lists only risks with an open gap" | none | none | 6.1 | CA-5 | 6.1 INFERRED; CA-5 INFERRED, docs only |
| Deterministic regeneration, template set matches standards | `regen`, `templates`: "regenerate twice is byte-identical" | Art. 17 | none | none | none | INFERRED |
| Deny-by-default roles, separation of duties on approval | `rbac.py`: "rbac selftest 20/20" | none | none | none | AC-3, AC-5, AC-6 | INFERRED, docs only; PARTIAL because nothing authenticates and the pipeline does not call it |

The workflow rules in the CI controls section below carry their own mapping to NIST SSDF and SLSA ids in `evidence/ci-controls.json`, each labeled GROUNDED or INFERRED with a source URL.

## How an auditor reproduces this in 2 minutes

1. Run `python3 claimdiode.py demo`. Confirm the last line is `demo: 2/2 expectations met` and the exit code is 0. The tamper step ending in `7 of 12 claims INVALIDATED, verify exit 1` is the expected result, not a failure.
2. Run `python3 claimdiode.py --selftest`. Confirm the last two lines are `claimdiode mutants killed 12/12` and `claimdiode selftest 30/30`.
3. Run `python3 grc_autofill.py --selftest`. Confirm the last line is `grc-autofill selftest 28/28`. Read the `PLANTED` lines (7 of the 28): each one is a defect the tool must catch.
4. Run `python3 trace.py check`. Confirm `trace: 38/38 rows verify`, then open `TRACE-MATRIX.tsv` and spot-check that a GROUNDED row names an enforcing case you can find in the selftest output.
5. Run `python3 rbac.py --selftest`. Confirm `rbac selftest 20/20`.
6. Run `python3 trace.py escalate --findings examples/findings.json --out <scratch dir>`. Confirm `escalate: 3 issues from 7 findings` and read one JSON file. Nothing is sent anywhere.
7. Run `pytest -q`. Real result in this working tree: `38 passed`, of which 10 are the CI-controls tests described below.

## Design decisions

- Fill facts, leave judgments empty. Templates carry two placeholder kinds, and the tool structurally cannot fill `{{J.NAME}}`. A boundary, a narrative, a risk acceptance and a sign-off belong to a person.
- Missing evidence lowers a count instead of becoming blank text. The final line is always `AUTO a/b fields filled, JUDGMENT n left`, so an absent input is visible in the number.
- Claim-level binding, not file-level. Each sentence carries an evidence id and a digest prefix, so a changed artifact names the exact claims, report and section it invalidates.
- Confidence is computed from the weakest link. An INFERRED crosswalk edge, INFERRED provenance or stale evidence caps a claim at LOW. Authors cannot raise it.
- Hash chain, link = sha256(prev + canonical json). A canonical form means the same content always yields the same link, which is what makes regeneration byte-identical and `git diff --exit-code` a usable gate.
- Reports and standards are data. A template dropped in `templates/` becomes a report with no code edit, and the selftest checks that.
- Every rule must be able to go RED. `teeth` replays each rule against a mutant fixture, so a rule that stays green under its own mutant fails the run. Zero templates or zero items is never a pass.
- Provenance on every mapping. `fetched` and `basis` columns say whether a requirement was read or paraphrased, so an INFERRED row cannot be mistaken for a quoted one.
- Escalation is offline and rules are data. `ESCALATION.tsv` maps a finding kind to a severity, priority, owner role and SLA hours. The SLA values are policy inputs the author chose, copied into the ticket text, not measured.
- Synthetic everything. Nothing here can leak a real system because nothing real is in it.

## The contract

Templates carry two kinds of placeholder:

| Syntax | Meaning | What the tool does |
|---|---|---|
| `{{NAME}}` | AUTO field, resolved from evidence files | Fills it, or leaves `{{NAME}}` in place and counts it as unfilled |
| `{{J.NAME}}` | JUDGMENT field (boundary, narrative, risk acceptance, sign-off) | Never fills it. Counted as "left" |

Rules the tool enforces, each proven by a planted-defect case in `--selftest`:

- Missing evidence stays visible. No file, empty file, header-only table: the placeholder survives and the AUTO count drops. Nothing is blank-filled.
- Malformed evidence is caught. A TSV with a missing required column or a ragged row is treated as missing, named on stdout, and the run exits 1.
- Unknown placeholders are flagged. A typo like `{{CONTROL_CONT}}` is counted and left, never silently dropped.
- Judgment is never filled, even when evidence with a matching name exists.
- Controls without proof are flagged. In the control table, a control with no evidence path shows `NO-EVIDENCE`; one pointing at a file that does not exist shows `EVIDENCE-FILE-MISSING`.

The final stdout line is always `grc-autofill: AUTO a/b fields filled, JUDGMENT n left`.

## claim-diode

`claimdiode.py` binds each claim in a generated report to the hashed evidence behind it. Three properties:

- A claim cannot be rendered without an evidence id.
- A claim's confidence cannot exceed its weakest link. An INFERRED crosswalk edge, INFERRED provenance or stale evidence caps it at LOW.
- When an evidence artifact changes, every claim that cites it is listed as INVALIDATED, with its report and section, and `verify` exits 1.

Commands: `collect` (evidence JSON plus a `manifest.jsonl` hash chain, link = sha256(prev + canonical json)), `check` (5 policy-as-code rules in `rules/`), `report`, `oscal`, `verify`, `teeth` (each rule must go RED on its fixture in `mutants/`), `regen`, `demo`. Each prints its oracle line last, for example `chain: N/N links verify`, `digests: N/N artifacts match claims`, `claims: N/N have evidence id`, `confidence: N/N claims <= weakest link`, `teeth: N/N controls RED on mutant`, `oscal: N/N documents pass structural check`. Checked-in output lives in `examples/claimdiode-out/` (rebuilt using `--now 2026-11-02T00:00:00Z`). The OSCAL structure follows the 1.1.x model shape.

Prior art, credited plainly: hashed evidence, OSCAL output and CI gates already exist in [Mihirajmera/llm-redteam-evidence](https://github.com/Mihirajmera/llm-redteam-evidence) and [VibeTensor/attestix](https://github.com/VibeTensor/attestix). The new part here is claim-level binding, confidence propagation through the crosswalk, and automatic invalidation. Not found in a GitHub search on 2026-11-02; that is a search result, not a claim of being first.

CI: `.github/workflows/ci.yml` runs `pytest`, the selftests, the demo, regenerates the outputs and runs `git diff --exit-code` on them. It runs when this folder is its own repo (GitHub only reads `.github/` at a repository root).

## grc-autofill

Reports are not listed anywhere in the code. The tool lists the files in `templates/` and each one is a report. There are 11 templates: SSP, SAP/SAR, POA&M, AI RMF profile, CSF 2.0 profile, EU AI Act Annex IV, SOC 2 style controls report, model card, ML pipeline audit, and two sector packs (HIPAA Security Rule crosswalk, SR 11-7 model risk). `--all` fills the nine non-sector reports. Sector packs are filled on request by name and read rows from `sectors/`, each with a source URL, a quoted fragment and a `fetched` flag.

### Evidence files

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

`examples/evidence/` is a synthetic demo system (`acme-rag-assistant`). Every row in it is invented for this repo.

### Fan-out by data, not code

Add a report: drop `templates/my-report.md` in. Use `{{NAME}}` for any AUTO field already known to the tool and `{{J.NAME}}` for judgment. Start every `## section` with an `AUTO:` or `JUDGMENT:` line saying where it comes from. `--all` and `--selftest` pick it up with no code edit. (`--selftest` checks this: it drops a template into a scratch copy and asserts it becomes a report.)

Add a standard: add a row to `STANDARDS.tsv` (`standard`, `artifact`, `section_id`, `section_title`, `required_fields`, `source_url`, `fetched`). Set `fetched` to `yes` only where the text was actually read; otherwise use `structure-only`. The selftest fails if an `artifact` named there has no template.

Map a control to a framework: add a row to `CROSSWALK.tsv`. Leave a column blank unless a source grounds it, and say how in `basis`.

The only code edit is a brand-new AUTO field type (a new resolver in the `RES` table), which is a deliberate step.

## Files

```
grc_autofill.py      the tool and its selftest
templates/           11 report templates
STANDARDS.tsv        report structure per standard, with source_url and a fetched flag
CROSSWALK.tsv        control to framework mapping, with source and basis (provenance) columns
sectors/             sector packs (HIPAA Security Rule, SR 11-7) with source and fetched columns
examples/evidence/   synthetic demo inputs
examples/out/        generated output for the demo (selftest asserts it matches a fresh run)
claimdiode.py        claim-diode tool and its selftest
examples/model_manifest.json, examples/claims.tsv, rules/, mutants/
                     claim-diode inputs, policy-as-code rules and their mutant fixtures
examples/claimdiode-out/  claim-diode generated output (selftest asserts it matches a fresh run)
trace.py, TRACE-MATRIX.tsv, TRACE-MATRIX.md, ESCALATION.tsv
                     code-to-control trace matrix, its renderer and the offline escalation rules
rbac.py, rbac-policy.json
                     deny-by-default role check with separation of duties
docs/BLUEPRINT.md    engineering manual, with gaps listed
.github/workflows/ci.yml    CI gate
tests/               pytest wrapper around the selftests and the demo
LICENSE              MIT
```

## Teeth, not theater

`python3 grc_autofill.py --selftest` runs 28 checks and exits non-zero if any fails. 7 of the 28 are planted defects that the tool must catch: evidence deleted, a short TSV row, a required column removed, an unknown placeholder, a judgment field whose name matches real evidence, and an unknown control id in a sector pack, among others. It also asserts the template set is non-empty, so "zero templates, zero problems" cannot pass.

```
PASS PLANTED missing evidence file: placeholder kept and counted
PASS PLANTED malformed TSV (short row): caught, field left unfilled
...
grc-autofill selftest 28/28
```

## Trace matrix, blueprint and escalation

`TRACE-MATRIX.tsv` maps functions in `grc_autofill.py` and `claimdiode.py` to control ids (SOC 2 TSC 2017, EU AI Act articles, ISO/IEC 42001 clauses, NIST AI RMF subcategories), 38 rows in all, each row naming the selftest case that enforces it. A row is GROUNDED only where the requirement text was quoted from a fetched public page (EU AI Act Art. 9 to 15, from a non-primary mirror). Every other row is an INFERRED paraphrase, flagged as such.

```
python3 trace.py check        # last line: trace: 38/38 rows verify
python3 trace.py --selftest   # last line: trace selftest 19/19
python3 trace.py render       # writes TRACE-MATRIX.md
python3 trace.py escalate --findings examples/findings.json --out examples/escalate-out   # last line: escalate: 3 issues from 7 findings
```

`ESCALATION.tsv` holds the escalation rules as data, and `escalate` writes Jira-shaped JSON offline and sends nothing. `docs/BLUEPRINT.md` is the engineering manual and lists its gaps; role-based access control there is PARTIAL (a policy check exists, authentication and pipeline enforcement do not). `templates/ml-pipeline-audit.md` is a four-section report template. None of this is a compliance claim.

## Limitations in detail

- Not legal advice, and not an attestation. The output is a draft for a human assessor. Assessor review is required before any of it is relied on.
- EU AI Act Annex IV text in `STANDARDS.tsv` came from a non-primary mirror. Verify against the primary text before use. Risk classification of a system is a decision for the owner and counsel.
- ISO/IEC 42001 and ISO/IEC 27001 rows are clause ids and structure only. The standards' text is not public and was not fetched; the tool uses clause and Annex A identifiers, nothing more.
- AICPA SOC 2 rows are Trust Services Criteria ids and short criterion names only. The criteria text is AICPA copyrighted and is not reproduced or fetched.
- EU AI Act Annex IV primary source: Regulation (EU) 2024/1689 on EUR-Lex (`https://eur-lex.europa.eu/eli/reg/2024/1689/oj`). The EUR-Lex fetch on 2026-11-02 returned no text, so the Annex IV rows stay on the mirror and carry a `FETCH-FAILED` marker in `STANDARDS.tsv`; `tests/test_standards.py` fails if a mirror row loses that marker.
- OWASP LLM mappings in `CROSSWALK.tsv` are INFERRED from title matches, not from any authoritative mapping. The `basis` column says so on every such row. Verify before relying on them.
- Several CSF 2.0, AI RMF and Annex IV rows are structure only, as flagged in the `fetched` and `required_fields` columns of `STANDARDS.tsv`.
- The demo content is synthetic. It demonstrates the mechanism and says nothing about any real system.

## Honesty statement

Every number in this README is the printed output of a command in this folder, and `pytest` re-runs the selftests and the demo. The counts that sit outside printed lines (7 of 28 planted cases, 12 GROUNDED and 26 INFERRED matrix rows, 11 templates) come from counting the selftest output, the matrix and `templates/`. The demo system, its evidence and its model are synthetic. The novelty claim for claim-diode is a search result from one date, not a claim of being first.

## CI workflow controls

zizmor and actionlint already lint GitHub workflows, and this does not replace them. The addition is control evidence: four rules in Rego (`policy/ci/workflow.rego`) whose findings map to NIST SSDF and SLSA ids in `evidence/ci-controls.json`, with a GROUNDED or INFERRED label on every mapping and a primary-source URL, so an assessor can re-run the check.

| Rule | Catches |
|---|---|
| R1 | workflow-level write permissions |
| R2 | third-party action not pinned to a 40-character sha (owners `actions` and `github`, local and docker refs are skipped) |
| R3 | `pull_request_target` combined with a checkout of the PR head |
| R4 | `${{ github.event.* }}` expanded inside a `run:` script |

Every rule has a planted RED fixture in `fixtures/workflows/` and a GREEN twin in `fixtures/workflows/good/`. All fixtures are synthetic.

```
conftest test -p policy/ci fixtures/workflows/*.yml        # 6 findings across 4 files, exit 1
conftest test -p policy/ci fixtures/workflows/good/*.yml   # 20 tests, 20 passed, exit 0
pytest -q tests/test_ci_controls.py                        # 10 passed
```

The RED output names one rule per file, for example `R3 pull_request_target checks out the PR head in job check`. `pytest` asserts each RED fixture fails only its own rule and each GREEN twin passes. It skips those tests, loudly, when `conftest` is not installed.

Limits: only workflow-level permissions are checked (R1), job-level write scopes are not. R2 treats `actions/` and `github/` owners as first party. The rule set is four patterns, not a workflow security audit. `.github/workflows/ci.yml` does not yet install `conftest`, so these checks run locally until a pinned install step is added.
