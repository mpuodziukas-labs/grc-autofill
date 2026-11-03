# Plan of Action and Milestones (OSCAL POA&M shape) - {{J.SYSTEM_NAME}}

Report date: {{REPORT_DATE}}.

## poam-metadata
AUTO: REPORT_DATE, OPEN_RISK_COUNT
Open items from the risk register: {{OPEN_RISK_COUNT}} of {{RISK_COUNT}} risks.

## poam-items
AUTO: RISK-REGISTER.tsv rows whose open_gap starts with yes
{{POAM_TABLE}}

Scheduled completion dates, milestones and resources per item: {{J.MILESTONES}}

## accepted-exceptions
AUTO: EXCEPTIONS.tsv
{{EXCEPTION_COUNTS}}

{{EXCEPTION_TABLE}}

Which exceptions are accepted risk versus to be fixed: {{J.EXCEPTION_DISPOSITION}}

## guards-failing
AUTO: GUARDS.tsv
{{GUARD_RED_TABLE}}

## approval
JUDGMENT: owner
Risk acceptance authority and date: {{J.APPROVAL}}
