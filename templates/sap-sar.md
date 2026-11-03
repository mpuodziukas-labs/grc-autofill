# Security Assessment Plan and Report (OSCAL AP and AR shape) - {{J.SYSTEM_NAME}}

Report date: {{REPORT_DATE}}.

## assessment-plan-scope
AUTO: POLICIES.md Scope line, CONTROL_COUNT
{{SCOPE_STATEMENT}}
Controls in scope: {{CONTROL_COUNT}}. Assessor and independence statement: {{J.ASSESSOR}}

## assessment-methods
AUTO: oracle commands from CONTROLS.tsv (test method = run the oracle, read exit code)
{{CONTROL_ORACLE_LIST}}

Assessment objectives beyond the oracles: {{J.EXTRA_OBJECTIVES}}

## results-guards
AUTO: GUARDS.tsv last lint results
{{GUARD_STATS}}

Guards not at rc 0:

{{GUARD_RED_TABLE}}

## results-controls
AUTO: CONTROLS.tsv evidence check
{{CONTROL_TABLE}}

## findings-and-risks
AUTO: RISK-REGISTER.tsv
{{RISK_TABLE}}

Finding severity and assessor conclusions: {{J.CONCLUSIONS}}

## audit-trail
AUTO: AUDIT.md
{{AUDIT_EXCERPT}}
