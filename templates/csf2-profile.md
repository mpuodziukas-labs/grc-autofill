# NIST CSF 2.0 Organizational Profile - {{J.ORG_NAME}}

Report date: {{REPORT_DATE}}. Profile = Current and Target; Tier is an owner decision.

## scope-and-context
AUTO: POLICIES.md Scope line
{{SCOPE_STATEMENT}}
Mission, stakeholders and risk appetite: {{J.CONTEXT}}

## current-profile
AUTO: CONTROLS.tsv nist_csf column
Controls per Function: {{CSF_FUNCTION_COUNTS}}

{{CSF_CURRENT_TABLE}}

## target-profile
JUDGMENT: owner
Desired outcomes by category and priority: {{J.TARGET_PROFILE}}

## gap-analysis
AUTO: RISK-REGISTER.tsv open gaps
Open gaps: {{OPEN_RISK_COUNT}}

{{POAM_TABLE}}

Action plan and prioritization: {{J.ACTION_PLAN}}

## tier
JUDGMENT: owner
Selected Tier and rationale: {{J.TIER}}

## controls-evidence
AUTO: CONTROLS.tsv
{{CONTROL_TABLE}}
