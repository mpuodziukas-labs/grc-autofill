# HIPAA Security Rule crosswalk (45 CFR 164 Subpart C) - {{J.SYSTEM_NAME}}

Report date: {{REPORT_DATE}}. Engineering mapping of existing controls to Security Rule standards, draft for assessor review. It is not a compliance determination or an attestation.

## scope
AUTO: POLICIES.md Scope line
{{SCOPE_STATEMENT}}
Covered entity or business associate role, and the ePHI in scope: {{J.EPHI_SCOPE}}

## requirement-sources
AUTO: sectors/hipaa-security.tsv
{{HIPAA_ROW_STATUS}}

Quoted fragments are the first words of each standard as returned by the eCFR versioner API for the date in the source URL. Edge GROUNDED means the fragment itself names the function the control performs. INFERRED means the mapping is an engineering judgment to verify.

## requirement-to-control-map
AUTO: sectors/hipaa-security.tsv, CROSSWALK.tsv control ids
{{HIPAA_REQUIREMENT_TABLE}}

## control-evidence
AUTO: CONTROLS.tsv
{{CONTROL_TABLE}}

## gaps-and-addressable-decisions
JUDGMENT: owner
Standards with no mapped control, and the written rationale for each addressable specification: {{J.GAP_DECISIONS}}

## administrative-physical-and-organizational-safeguards
JUDGMENT: owner
Workforce, training, facility, device and business associate arrangements are outside the repository evidence: {{J.NON_TECHNICAL_SAFEGUARDS}}
