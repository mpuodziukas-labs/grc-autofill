# NIST AI RMF 1.0 Profile - {{J.SYSTEM_NAME}}

Report date: {{REPORT_DATE}}. Functions: GOVERN, MAP, MEASURE, MANAGE. Subcategory text is in STANDARDS.tsv where fetched.

## use-case-and-context
AUTO: POLICIES.md Scope line
{{SCOPE_STATEMENT}}
AI system purpose, users and affected parties: {{J.USE_CASE}}

## functions-coverage
AUTO: GUARDS.tsv tags column (NIST: tags), counted per function
{{AIRMF_FUNCTION_TABLE}}

## crosswalk
AUTO: CROSSWALK.tsv
{{CROSSWALK_COVERAGE}}

Subcategory mapping is blank unless a grounded source supplied it; owner fills the rest.

## govern
AUTO: POLICIES.md
{{POLICY_LIST}}
Accountability, roles and culture: {{J.GOVERN_NARRATIVE}}

## map
JUDGMENT: owner
Context, intended purpose, impacts, third-party risk. Owner narrative: {{J.MAP_NARRATIVE}}

## measure
AUTO: guard stats from GUARDS.tsv
{{GUARD_STATS}}
Metrics and TEVV method rationale: {{J.MEASURE_NARRATIVE}}

## manage
AUTO: RISK-REGISTER.tsv
{{RISK_TABLE}}
Prioritization and response decisions: {{J.MANAGE_NARRATIVE}}
