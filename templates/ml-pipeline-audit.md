# ML Pipeline Audit Report - {{J.PIPELINE_NAME}}

Report date: {{REPORT_DATE}}. Draft for a human assessor. Structure only: four sections, each declaring what is filled from evidence and what is left to a person. Not an attestation.

## 1 Algorithmic Traceability
AUTO: CONTROLS.tsv and CROSSWALK.tsv (control count, control table, crosswalk coverage)
Controls in scope: {{CONTROL_COUNT}}

{{CONTROL_TABLE}}

Crosswalk coverage:
{{CROSSWALK_COVERAGE}}

Code-to-control trace for the tooling itself: see `TRACE-MATRIX.md` in the kit (rendered by `python3 trace.py render`).
Pipeline boundary, model lineage and training-data provenance: {{J.TRACE_SCOPE}}

## 2 Data Lifecycle Controls
AUTO: POLICIES.md and RISK-REGISTER.tsv (scope line, policy list, risk table)
Scope: {{SCOPE_STATEMENT}}

Policies:
{{POLICY_LIST}}

Risks recorded: {{RISK_COUNT}}, with an open gap: {{OPEN_RISK_COUNT}}

{{RISK_TABLE}}

Retention, deletion and lineage decisions: {{J.DATA_LIFECYCLE}}

## 3 Continuous Compliance Logging
AUTO: GUARDS.tsv, EVIDENCE-INDEX.md and EXCEPTIONS.tsv (automated checks, receipts, exceptions)
Automated checks recorded: {{GUARD_COUNT}}

{{GUARD_STATS}}

Checks currently failing:
{{GUARD_RED_TABLE}}

Evidence commands and receipts:
{{EVIDENCE_COMMAND_TABLE}}

Exceptions:
{{EXCEPTION_COUNTS}}

{{EXCEPTION_TABLE}}

Log retention period and who reviews the log: {{J.LOG_REVIEW}}

## 4 Automated Jira Escalation Rules
AUTO: RISK-REGISTER.tsv (open gaps that need a ticket)
Open risks that need a ticket today: {{OPEN_RISK_COUNT}}

{{POAM_TABLE}}

Escalation rules are data in `ESCALATION.tsv` (rule id, trigger, severity, Jira priority, labels, owner role, SLA hours). `python3 trace.py escalate` turns claim-diode findings into Jira-shaped JSON files offline; it sends nothing. Examples are in `examples/escalate-out/`.
Rule owners, SLA values and sign-off: {{J.ESCALATION_SIGNOFF}}
