# Blueprint: engineering manual for grc-autofill and claim-diode

Each numbered section below says what the repo does, names the function and file that do it, and names the selftest case (the exact string printed by `--selftest`) that fails if it stops. Where the repo does not do something, the section says NOT IMPLEMENTED, in plain words, and gives the design only. This manual describes mechanisms and what their tests show. It does not claim certification, audit readiness, or compliance with any framework or law. Everything the tools run on is synthetic.

Commands that print the oracle lines quoted here: `python3 grc_autofill.py --selftest`, `python3 claimdiode.py --selftest`, `python3 trace.py --selftest`, `python3 trace.py check`.

## 1 Scope

1.1 In scope: the two tools in this folder, their evidence inputs, their generated reports, and the trace and escalation files added around them.
- `grc_autofill.py` fills the mechanical fields of report templates from evidence files and leaves judgment fields empty.
- `claimdiode.py` binds each report claim to hashed evidence, caps claim confidence at its weakest link, and lists claims as INVALIDATED when their evidence changes.
- `trace.py` checks and renders `TRACE-MATRIX.tsv` (code to control ids) and turns findings into Jira-shaped JSON using `ESCALATION.tsv`.

1.2 Out of scope: any real system. The demo system `acme-rag-assistant`, its evidence and its mock model are synthetic. Nothing here assesses a real product.

1.3 No network access. The three tools import no network module; `trace.py escalate` writes files and sends nothing.

## 2 Definitions

2.1 AUTO field: a `{{NAME}}` placeholder resolved from evidence by a resolver in the `RES` table of `grc_autofill.py`. JUDGMENT field: a `{{J.NAME}}` placeholder that is never filled.
2.2 Evidence: a JSON document in `examples/claimdiode-out/evidence/` (claim-diode) or a fixed-name file in `examples/evidence/` (grc-autofill).
2.3 Claim: one sentence in a report with a claim id, provenance, evidence ids and a confidence level.
2.4 INVALIDATED: a claim whose evidence digest, chain link, annotation or confidence bound no longer verifies.
2.5 Matrix row: one line in `TRACE-MATRIX.tsv` naming a function, a control id, a basis (GROUNDED means the control text was quoted from a fetched public source; INFERRED means a short paraphrase that must be verified), and the selftest case that enforces it.
2.6 Finding: one JSON object with a `kind`, produced from claim-diode output and read by `trace.py escalate`.

## 3 Data minimization

3.1 Fixed inputs only. `evidence_paths` in `grc_autofill.py` builds paths from the fixed table `FILES`; the tool reads those eight file names and nothing else. Enforced by: "PLANTED missing evidence file: placeholder kept and counted".
3.2 Capped excerpts. `_r_audit` copies at most 15 non-blank lines of `AUDIT.md`; `_cell` removes pipes and newlines from table cells. Enforced by: "all AUTO filled when evidence present".
3.3 Digests, not copies. claim-diode annotates a claim with a sha256 digest prefix and stores evidence as small JSON metrics in `collect` (`claimdiode.py`). Enforced by: "manifest binds the exact system prompt digest".
3.4 Personal-data echo test. `run_tests` sends synthetic PII probes to the mock model and the EV-PII entry of `DETECT` (using `PII_RE`) counts echoes; rule R-03 requires zero. Enforced by: "each injected flaw turns exactly its own rule FAIL".
3.5 GAP, NOT IMPLEMENTED: no test scans the evidence directories for personal data, and there is no retention or deletion job. Design: a rule that runs `PII_RE` over every evidence file and fails closed, plus a documented retention period carried in `POLICIES.md` and checked against file dates.

## 4 Alignment and evaluation auditing

4.1 Probe families. `run_tests` (`claimdiode.py`) exercises the mock model with five families: prompt-injection leak, harmful-request refusal, PII echo, output schema (`_schema_ok`), and tool-call allowlist (`TOOLS`). The model is a deterministic mock with an injectable flaw (`mock_model`); it says nothing about any real model.
4.2 Rules as data. `rules/R-01.json` to `R-05.json` hold a threshold per metric; `check`, `rule_status` and `eval_value` evaluate them. A missing or non-numeric metric is NOT_TESTED and never PASS. Enforced by: "each injected flaw turns exactly its own rule FAIL", "clean mock model passes all 5 rules", "injected flaw makes check FAIL R-01 and exit 1".
4.3 Rules must be able to fail. `teeth` replays each rule against its fixture in `mutants/` and requires RED. Enforced by: "teeth on clean rules: 5/5" and "PLANTED toothless rule (stays GREEN under its own mutant)".
4.4 Stale evidence cannot pass. `is_stale` and `rule_status` mark old evidence STALE and `bound` caps claim confidence at LOW. Enforced by: "PLANTED evidence older than max-age: STALE, capped LOW, verify fails".
4.5 Confidence is computed, not authored. `bound` and `edge_info` cap a claim at its weakest link. Enforced by: "confidence: INFERRED edge or class caps LOW, JUDGMENT MEDIUM, grounded AUTO HIGH" and "PLANTED upgrade an INFERRED-edge claim to HIGH".
4.6 Limit: five probe families with three or four prompts each are a demonstration of the mechanism, not an evaluation of any model.

## 5 Role-based access control

5.1 PARTIAL. `rbac.py` is a deny-by-default policy check: `rbac-policy.json` maps four roles (viewer, analyst, approver, admin) to four actions (read_report, edit_judgment, approve_report, change_rules). Anything not granted is denied, an unknown role or action is denied, and a missing or malformed policy (or one with a wildcard grant) denies everything. `approve_report` has separation of duties: the actor must differ from the author, and both must be supplied. Every decision is appended to an audit record with a reason (`--audit-log FILE` writes JSONL). Run it as `python3 rbac.py check <role> <action> [--author X --actor Y]` (exit 0 allow, 1 deny). Enforced by: `python3 rbac.py --selftest` (last line `rbac selftest N/N`, includes PLANTED self-approval, unknown role, unknown action, wildcard grant and missing policy cases), `tests/test_rbac.py`, and the `rbac selftest and policy checks` step in `.github/workflows/ci.yml`.
5.1a What it does not do: it does not authenticate anyone, since role, actor and author are strings the caller passes in. It is not called by `grc_autofill.py`, `claimdiode.py` or `trace.py`, so the pipeline does not yet refuse an action on its own. The audit log is a plain file the caller controls and is not tamper-evident. The `owner_role` column in `ESCALATION.tsv` is still a label copied into a ticket description.
5.2 What exists and is sometimes mistaken for RBAC:
- Judgment is reserved to people by data, not by identity: `fill_text` never fills a `{{J.NAME}}` field. Enforced by: "PLANTED judgment field with matching evidence: never filled".
- Tool least-privilege inside the mock pipeline: `TOOLS` is an allowlist and rule R-05 fails on any call outside it. Enforced by: "each injected flaw turns exactly its own rule FAIL". This is model tool scope, not user access control.
5.3 Design (NOT IMPLEMENTED; the role-to-action mapping now exists as `rbac-policy.json`, the rest below does not): wire `rbac.py` into the report write path; judgment fields carry a signer id and a detached signature that `fill_text` verifies before accepting text; `trace.py escalate` refuses a rule whose `owner_role` is not in `ROLES.tsv`. Each of these would need its own planted-defect selftest before it counts.

## 6 Change control

6.1 Evidence changes are detected. `chain_check` re-walks the hash chain in `manifest.jsonl` (link = sha256 of previous link plus canonical JSON). Enforced by: "hash chain: 7/7 links verify on clean output" and "PLANTED break one hash-chain link".
6.2 Documents change only with evidence. `verify` lists every claim whose evidence changed as INVALIDATED with its report and section and exits 1. Enforced by: "PLANTED flip one byte in the model manifest copy" and "demo: tamper shows 7 of 12 INVALIDATED (exit 1), regen clears it".
6.3 Output is reproducible. `regen` rebuilds every artifact; the checked-in outputs must equal a fresh run. Enforced by: "regenerate twice is byte-identical", "checked-in examples/claimdiode-out equals a fresh regenerate", "examples/out is exactly what the demo evidence generates".
6.4 Reports are data. A template dropped in `templates/` becomes a report; each artifact in `STANDARDS.tsv` must have a template and the reverse. Enforced by: "every artifact named in STANDARDS.tsv has a template and vice versa" and "fan-out by data: a dropped template is a new report, no code edit".
6.5 The trace matrix is itself under change control: `trace.py check` fails when a named function is renamed or removed, when a control id is malformed, or when a named test no longer exists. Enforced by: "PLANTED renamed function: caught", "PLANTED malformed control id: caught", "PLANTED missing test name: caught" (`trace.py --selftest`).
6.6 A CI workflow file exists at `.github/workflows/ci.yml`. It was not run as part of this section and it only runs when this folder is its own repository.
6.7 GAP, NOT IMPLEMENTED: there is no approval step. Nothing stops an author from editing a rule threshold and regenerating. Design: a two-person rule on `rules/` and `ESCALATION.tsv` enforced by the hosting platform, outside this code.

## 7 Continuous compliance logging

7.1 Evidence log. `collect` appends one record per evidence document to `manifest.jsonl` (sequence, id, path, previous link, digest, link). Enforced by: "regen on the clean examples exits 0 with 5/5 stages" and "hash chain: 7/7 links verify on clean output".
7.2 Every command prints its oracle line last (`chain: N/N links verify`, `checks: N/N rules PASS`, `digests: N/N artifacts match claims`, `trace: N/N rows verify`) and exits non-zero on failure, so a scheduler can log and gate on it. Zero items is never a pass: "verify on an empty work dir fails (zero items is not a pass)" and "PLANTED empty matrix: not a pass".
7.3 Each rendered claim carries its evidence digest. `report` writes the annotation and `verify` checks it. Enforced by: "every claim is rendered in its report section with its annotation" and "PLANTED strip a claim's annotation from the rendered report".
7.4 Limit: the chain is tamper-evident inside one working directory. Someone who can rewrite the chain, the claims lock and the evidence together produces a consistent set. GAP, NOT IMPLEMENTED: anchoring the head link outside the directory (for example in a signed commit or a timestamping service).
7.5 PARTIAL: the workflow in `.github/workflows/ci.yml` has a daily `schedule:` cron and `workflow_dispatch:`, so the gate reruns without a push. It has not been observed running on a schedule from this section, and it only runs when this folder is its own repository. The tools themselves still do not schedule anything.

## 8 Escalation

8.1 Rules are data. `ESCALATION.tsv` holds `rule_id`, `trigger`, `severity`, `jira_priority`, `labels`, `owner_role`, `sla_hours`. Triggers are the finding kinds listed in `TRIGGERS` in `trace.py`; each is tied to a word that must still appear in the tool that emits it.
8.2 `trace.py escalate` turns findings into one Jira-shaped JSON file per rule that fired, with `project`, `issuetype`, `summary`, `priority`, `labels` and a description that lists the findings and the control ids from the matrix for the enforcing function. Findings can come from a JSON list or from `claimdiode.py verify` output (`--verify-log`, INVALIDATED lines only). Enforced by: "escalate: 7 findings give Jira-shaped issues with control ids, equal to checked-in examples/escalate-out" and "escalate: a claimdiode verify INVALIDATED line parses to the checked-in finding".
8.3 A rule that can never match is an error: "PLANTED rule whose trigger is unknown (never matches): caught" and "PLANTED trigger word gone from the source (never matches): caught".
8.4 A finding no rule matches is reported UNROUTED and the command exits 1: "PLANTED finding no rule matches: reported UNROUTED, exit 1".
8.5 `sla_hours` values are policy inputs chosen by the author. They are copied into the ticket text and are not measured or enforced.
8.6 GAP, NOT IMPLEMENTED: nothing is sent to Jira. There is no HTTP client, no credential handling, and no de-duplication against existing tickets. Only INVALIDATED lines have a producer from tool output; the other triggers need a findings file supplied by the caller. Design: a separate sender that reads the JSON files, searches by a label plus finding id before creating, and is the only component allowed network access.

## 9 Limitations

9.1 This is not legal advice, an attestation, or evidence that any control framework or law is met. The matrix maps functions to requirement ids for engineers and reviewers.
9.2 Basis counts are in `TRACE-MATRIX.md`. INFERRED rows are paraphrases that have not been checked against the standard. ISO/IEC 42001 rows use clause ids only; the standard's text is not public and was not read. SOC 2 rows use criterion ids and short titles only.
9.3 EU AI Act article text was read from a non-primary mirror. Verify against the Official Journal before use. Annex IV rows are INFERRED for that reason.
9.4 Mapping a function to an article is by analogy. For example, the evidence hash chain is an evidence log, not the event logging of a deployed high-risk system that Article 12 describes.
9.5 Everything runs on synthetic data and a deterministic mock model. Results say what the mechanisms do on that data.
9.6 Sections 3.5, 5, 6.7, 7.4, 7.5 and 8.6 are gaps. They are listed so nobody has to find them.
