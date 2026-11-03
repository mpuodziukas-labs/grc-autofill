# SOC 2 style Controls Report (self-assessment, not an attestation) - {{J.SYSTEM_NAME}}

Report date: {{REPORT_DATE}}. This is an internal description of controls, not a CPA examination.

## system-description
AUTO: POLICIES.md Scope line
{{SCOPE_STATEMENT}}
Services, infrastructure, people, data and boundaries: {{J.SYSTEM_DESCRIPTION}}

## trust-services-criteria-matrix
AUTO: CONTROLS.tsv soc2_tsc column
{{SOC2_CONTROL_MATRIX}}

Guard support per criterion (GUARDS.tsv tags):

{{SOC2_GUARD_COUNTS}}

Categories in scope (Security always; others by choice): {{J.CATEGORIES_IN_SCOPE}}

## control-descriptions-and-tests
AUTO: CONTROLS.tsv
{{CONTROL_TABLE}}

## test-results
AUTO: GUARDS.tsv last lint results
{{GUARD_STATS}}

{{GUARD_RED_TABLE}}

## exceptions-noted
AUTO: EXCEPTIONS.tsv
{{EXCEPTION_COUNTS}}

{{EXCEPTION_TABLE}}

Management response to exceptions: {{J.MANAGEMENT_RESPONSE}}

## complementary-user-and-subservice-controls
JUDGMENT: owner
Subservice organizations and user entity responsibilities: {{J.SUBSERVICE}}
