# SR 11-7 model risk management mapping - {{J.MODEL_NAME}}

Report date: {{REPORT_DATE}}. Engineering mapping of existing controls to the SR 11-7 / OCC 2011-12 guidance areas, draft for assessor review. It is not a validation report or an examiner-facing conformance statement.

## scope
AUTO: POLICIES.md Scope line
{{SCOPE_STATEMENT}}
Model purpose, owner, and materiality tier: {{J.MODEL_SCOPE}}

## requirement-sources
AUTO: sectors/sr-11-7.tsv
{{SR117_ROW_STATUS}}

Rows marked fetched=no have no quoted text: the guidance body could not be retrieved, so titles are from memory and every edge is INFERRED until verified against the primary text.

## guidance-area-to-control-map
AUTO: sectors/sr-11-7.tsv, CROSSWALK.tsv control ids
{{SR117_REQUIREMENT_TABLE}}

## control-evidence
AUTO: CONTROLS.tsv
{{CONTROL_TABLE}}

## conceptual-soundness-and-outcomes-analysis
JUDGMENT: independent validator
Conceptual soundness review, benchmark and back-testing results, and effective challenge record: {{J.VALIDATION_RESULTS}}

## governance-and-inventory
JUDGMENT: owner
Board and senior management roles, model inventory entry, policy references and vendor model handling: {{J.GOVERNANCE_NOTES}}
