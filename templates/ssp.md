# System Security Plan (OSCAL SSP shape) - {{J.SYSTEM_NAME}}

Report date: {{REPORT_DATE}}. Structure follows OSCAL SSP top-level fields (see STANDARDS.tsv).

## metadata
AUTO: REPORT_DATE
Title: {{J.SYSTEM_NAME}}; version {{J.VERSION}}; date {{REPORT_DATE}}.

## system-characteristics
AUTO: POLICIES.md Scope line
{{SCOPE_STATEMENT}}

Sensitivity and impact level: {{J.IMPACT_LEVEL}}
System description and authorization boundary: {{J.BOUNDARY}}

## system-implementation
AUTO: POLICIES.md policy headings, GUARD_COUNT from GUARDS.tsv
Policies in force:
{{POLICY_LIST}}

Guards registered: {{GUARD_COUNT}}. Users, roles and inventory: {{J.ROLES_AND_INVENTORY}}

## control-implementation
AUTO: CONTROLS.tsv (enforcer, oracle, evidence, cadence; Check column flags missing evidence)
Controls: {{CONTROL_COUNT}}

{{CONTROL_TABLE}}

Responsible role and implementation narrative per control: {{J.CONTROL_NARRATIVE}}

## risk-and-exceptions
AUTO: RISK-REGISTER.tsv, EXCEPTIONS.tsv
Risks: {{RISK_COUNT}}; open gaps: {{OPEN_RISK_COUNT}}. Exceptions by class: {{EXCEPTION_COUNTS}}

## back-matter
AUTO: EVIDENCE-INDEX.md
{{EVIDENCE_COMMAND_TABLE}}

Authorizing official and sign-off: {{J.SIGNOFF}}
