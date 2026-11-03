# ML Pipeline Audit Report - {{J.PIPELINE_NAME}}

Report date: 2026-11-02. Draft for a human assessor. Structure only: four sections, each declaring what is filled from evidence and what is left to a person. Not an attestation.

## 1 Algorithmic Traceability
AUTO: CONTROLS.tsv and CROSSWALK.tsv (control count, control table, crosswalk coverage)
Controls in scope: 8

| Control | Name | Enforcer | Oracle command | Evidence path | Cadence | Check |
|---|---|---|---|---|---|---|
| C-01 | Retrieval ACL filter | src/retrieval/acl_filter.py | make verify-acl | receipts/c-01.txt | weekly | ok |
| C-02 | PII scrub on ingest | src/ingest/scrub.py | make verify-scrub | receipts/c-02.txt | weekly | ok |
| C-03 | Prompt template pinning | prompts/LOCK.sha256 | make verify-prompts | receipts/c-03.txt | per-release | ok |
| C-04 | Output citation check | src/answer/cite_check.py | make verify-cites |  | weekly | NO-EVIDENCE |
| C-05 | Rate and spend limits | infra/limits.yaml | make verify-limits | receipts/c-05.txt | monthly | ok |
| C-06 | Model version allowlist | infra/models.allow | make verify-models | receipts/c-06-missing.txt | per-release | EVIDENCE-FILE-MISSING |
| C-07 | Human review queue | src/answer/review_queue.py | make verify-queue | receipts/c-07.txt | weekly | ok |
| C-08 | Log retention and redaction | infra/logging.yaml | make verify-logs | receipts/c-08.txt | monthly | ok |

Crosswalk coverage:
rows 14; ai_rmf_function non-blank 5; ai_rmf_subcategory non-blank 14; csf2 non-blank 8; iso42001_clause non-blank 4; eu_ai_act_article non-blank 0; owasp_llm non-blank 6

Code-to-control trace for the tooling itself: see `TRACE-MATRIX.md` in the kit (rendered by `python3 trace.py render`).
Pipeline boundary, model lineage and training-data provenance: {{J.TRACE_SCOPE}}

## 2 Data Lifecycle Controls
AUTO: POLICIES.md and RISK-REGISTER.tsv (scope line, policy list, risk table)
Scope: Scope: the acme-rag-assistant service, its vector index, prompt templates and the staff who operate it.

Policies:
- P1. Change management
- P2. Access control
- P3. Data handling
- P4. Incident response

Risks recorded: 6, with an open gap: 3

| Risk | What could go wrong | Impact | Likelihood | Inherent | Controls | Residual | Treatment | Open gap |
|---|---|---|---|---|---|---|---|---|
| R-01 | a user retrieves another team's documents | 5 | 3 | 15 | C-01;C-08 | 5 | mitigate | no |
| R-02 | personal data is embedded and later surfaced in answers | 5 | 3 | 15 | C-02 | 10 | mitigate | yes: scrub misses free-text names in scanned PDFs |
| R-03 | a prompt edit bypasses review and weakens refusals | 4 | 3 | 12 | C-03 | 4 | mitigate | no |
| R-04 | the assistant answers confidently without a source | 3 | 4 | 12 | C-04;C-07 | 9 | mitigate | yes: citation check not yet run on streaming answers |
| R-05 | token spend spikes from a looping client | 3 | 3 | 9 | C-05 | 3 | mitigate | no |
| R-06 | a provider silently swaps the model version | 4 | 2 | 8 | C-06 | 8 | accept | yes: no provider change notice feed |

Retention, deletion and lineage decisions: {{J.DATA_LIFECYCLE}}

## 3 Continuous Compliance Logging
AUTO: GUARDS.tsv, EVIDENCE-INDEX.md and EXCEPTIONS.tsv (automated checks, receipts, exceptions)
Automated checks recorded: 6

guards 6; with selftest 5; last lint rc 0: 4; rc non-zero: 1; UNKNOWN: 1

Checks currently failing:
| Guard | Statement | Last lint rc | Time |
|---|---|---|---|
| g-cites | every answer carries a source id | 1 | 2026-11-01T06:00:00Z |

Evidence commands and receipts:
| Control | Command | Receipt |
|---|---|---|
| C-01 | `make verify-acl` | `receipts/c-01.txt` |
| C-02 | `make verify-scrub` | `receipts/c-02.txt` |
| C-03 | `make verify-prompts` | `receipts/c-03.txt` |
| C-05 | `make verify-limits` | `receipts/c-05.txt` |
| C-07 | `make verify-queue` | `receipts/c-07.txt` |
| C-08 | `make verify-logs` | `receipts/c-08.txt` |

Exceptions:
ACCEPTED: 2; OPEN: 3

| Id | Class | Cause | Age (days) | Owner |
|---|---|---|---|---|
| ex-004 | ACCEPTED | provider notice feed unavailable | 60 | platform-lead |
| ex-001 | OPEN | owner not yet assigned for scanned-PDF scrub | 41 | data-lead |
| ex-002 | ACCEPTED | citation check skipped for streaming answers until v2 | 23 | eval-lead |
| ex-003 | OPEN | receipt for C-06 not yet captured | 12 | eval-lead |
| ex-005 | OPEN | flaky retrieval latency check | 5 | platform-lead |

Showing 5 of 5 exception rows (oldest first).

Log retention period and who reviews the log: {{J.LOG_REVIEW}}

## 4 Automated Jira Escalation Rules
AUTO: RISK-REGISTER.tsv (open gaps that need a ticket)
Open risks that need a ticket today: 3

| Item | Weakness | Risk | Controls | Residual | Status | Owner / due / milestones |
|---|---|---|---|---|---|---|
| P-R-02 | scrub misses free-text names in scanned PDFs | personal data is embedded and later surfaced in answers | C-02 | 10 | open | owner to set |
| P-R-04 | citation check not yet run on streaming answers | the assistant answers confidently without a source | C-04;C-07 | 9 | open | owner to set |
| P-R-06 | no provider change notice feed | a provider silently swaps the model version | C-06 | 8 | open | owner to set |

Escalation rules are data in `ESCALATION.tsv` (rule id, trigger, severity, Jira priority, labels, owner role, SLA hours). `python3 trace.py escalate` turns claim-diode findings into Jira-shaped JSON files offline; it sends nothing. Examples are in `examples/escalate-out/`.
Rule owners, SLA values and sign-off: {{J.ESCALATION_SIGNOFF}}
