# NIST CSF 2.0 Organizational Profile - {{J.ORG_NAME}}

Report date: 2026-11-02. Profile = Current and Target; Tier is an owner decision.

## scope-and-context
AUTO: POLICIES.md Scope line
Scope: the acme-rag-assistant service, its vector index, prompt templates and the staff who operate it.
Mission, stakeholders and risk appetite: {{J.CONTEXT}}

## current-profile
AUTO: CONTROLS.tsv nist_csf column
Controls per Function: DE: 5; GV: 1; ID: 1; PR: 8; RS: 1

| CSF 2.0 id | Controls (current) | Count |
|---|---|---|
| DE.AE-02 | C-07 | 1 |
| DE.CM-01 | C-05 | 1 |
| DE.CM-03 | C-08 | 1 |
| DE.CM-09 | C-03, C-04 | 2 |
| GV.SC-07 | C-06 | 1 |
| ID.IM-03 | C-04 | 1 |
| PR.AA-05 | C-01 | 1 |
| PR.DS-01 | C-01, C-02 | 2 |
| PR.DS-02 | C-02 | 1 |
| PR.IR-04 | C-05 | 1 |
| PR.PS-01 | C-03, C-06 | 2 |
| PR.PS-04 | C-08 | 1 |
| RS.MA-01 | C-07 | 1 |

## target-profile
JUDGMENT: owner
Desired outcomes by category and priority: {{J.TARGET_PROFILE}}

## gap-analysis
AUTO: RISK-REGISTER.tsv open gaps
Open gaps: 3

| Item | Weakness | Risk | Controls | Residual | Status | Owner / due / milestones |
|---|---|---|---|---|---|---|
| P-R-02 | scrub misses free-text names in scanned PDFs | personal data is embedded and later surfaced in answers | C-02 | 10 | open | owner to set |
| P-R-04 | citation check not yet run on streaming answers | the assistant answers confidently without a source | C-04;C-07 | 9 | open | owner to set |
| P-R-06 | no provider change notice feed | a provider silently swaps the model version | C-06 | 8 | open | owner to set |

Action plan and prioritization: {{J.ACTION_PLAN}}

## tier
JUDGMENT: owner
Selected Tier and rationale: {{J.TIER}}

## controls-evidence
AUTO: CONTROLS.tsv
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
