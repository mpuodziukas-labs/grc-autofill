# SOC 2 style Controls Report (self-assessment, not an attestation) - {{J.SYSTEM_NAME}}

Report date: 2026-11-02. This is an internal description of controls, not a CPA examination.

## system-description
AUTO: POLICIES.md Scope line
Scope: the acme-rag-assistant service, its vector index, prompt templates and the staff who operate it.
Services, infrastructure, people, data and boundaries: {{J.SYSTEM_DESCRIPTION}}

## trust-services-criteria-matrix
AUTO: CONTROLS.tsv soc2_tsc column
| Criterion | Controls | Count |
|---|---|---|
| A1.1 | C-05 | 1 |
| C1.1 | C-02 | 1 |
| CC4.1 | C-08 | 1 |
| CC6.1 | C-01 | 1 |
| CC6.7 | C-02 | 1 |
| CC7.2 | C-04, C-05, C-08 | 3 |
| CC7.3 | C-07 | 1 |
| CC7.4 | C-07 | 1 |
| CC8.1 | C-03, C-06 | 2 |
| CC9.2 | C-06 | 1 |

Guard support per criterion (GUARDS.tsv tags):

| Criterion | Guard count |
|---|---|
| A1 | 1 |
| CC6 | 2 |
| CC7 | 1 |
| CC8 | 1 |

Categories in scope (Security always; others by choice): {{J.CATEGORIES_IN_SCOPE}}

## control-descriptions-and-tests
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

## test-results
AUTO: GUARDS.tsv last lint results
guards 6; with selftest 5; last lint rc 0: 4; rc non-zero: 1; UNKNOWN: 1

| Guard | Statement | Last lint rc | Time |
|---|---|---|---|
| g-cites | every answer carries a source id | 1 | 2026-11-01T06:00:00Z |

Claims bound to evidence (claimdiode):
- 8 controls are registered and 6 have a receipt file on disk. [claim CD-09 | sha256:57be143ccf37adcd | AUTO | HIGH | ev:EV-CTRL]

## exceptions-noted
AUTO: EXCEPTIONS.tsv
ACCEPTED: 2; OPEN: 3

| Id | Class | Cause | Age (days) | Owner |
|---|---|---|---|---|
| ex-004 | ACCEPTED | provider notice feed unavailable | 60 | platform-lead |
| ex-001 | OPEN | owner not yet assigned for scanned-PDF scrub | 41 | data-lead |
| ex-002 | ACCEPTED | citation check skipped for streaming answers until v2 | 23 | eval-lead |
| ex-003 | OPEN | receipt for C-06 not yet captured | 12 | eval-lead |
| ex-005 | OPEN | flaky retrieval latency check | 5 | platform-lead |

Showing 5 of 5 exception rows (oldest first).

Management response to exceptions: {{J.MANAGEMENT_RESPONSE}}

Claims bound to evidence (claimdiode):
- 2 registered controls have no receipt file on disk. [claim CD-10 | sha256:57be143ccf37adcd | AUTO | HIGH | ev:EV-CTRL]

## complementary-user-and-subservice-controls
JUDGMENT: owner
Subservice organizations and user entity responsibilities: {{J.SUBSERVICE}}
