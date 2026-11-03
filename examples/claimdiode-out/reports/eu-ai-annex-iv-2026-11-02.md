# EU AI Act Annex IV Technical Documentation - {{J.SYSTEM_NAME}}

Report date: 2026-11-02. Annex IV points 1-9 per STANDARDS.tsv (text from a non-primary mirror; VERIFY AGAINST PRIMARY TEXT). Risk classification of the system is an owner and counsel decision. Not legal advice; have a licensed attorney review.

## point-1-general-description
JUDGMENT: owner
Intended purpose, provider, versions, hardware, interfaces: {{J.GENERAL_DESCRIPTION}}

Claims bound to evidence (claimdiode):
- The test evidence in this report is bound to model manifest sha256 910c22ca8a5c. [claim CD-07 | sha256:d3ece036794de76f | AUTO | HIGH | ev:EV-MODEL]

## point-2-development-process
AUTO: CONTROLS.tsv enforcers and oracles (development and teeth-testing controls)
- C-01: `make verify-acl`
- C-02: `make verify-scrub`
- C-03: `make verify-prompts`
- C-04: `make verify-cites`
- C-05: `make verify-limits`
- C-06: `make verify-models`
- C-07: `make verify-queue`
- C-08: `make verify-logs`
Design specifications, data requirements, training methods: {{J.DEVELOPMENT_DETAIL}}

## point-3-monitoring-and-control
AUTO: guard stats, audit excerpt
guards 6; with selftest 5; last lint rc 0: 4; rc non-zero: 1; UNKNOWN: 1

{{AUDIT_EXCERPT}}

Capabilities, limitations, accuracy levels, human oversight measures: {{J.CAPABILITIES_LIMITS}}

Claims bound to evidence (claimdiode):
- 0 tool calls fell outside the allowlist in 3 tool probes. [claim CD-06 | sha256:b3817b6c3f0c7d51 | AUTO | HIGH | ev:EV-MODEL,EV-TOOL]

## point-4-performance-metrics
JUDGMENT: owner
Why the chosen metrics are appropriate: {{J.METRICS_RATIONALE}}

## point-5-risk-management-system
AUTO: RISK-REGISTER.tsv
| Risk | What could go wrong | Impact | Likelihood | Inherent | Controls | Residual | Treatment | Open gap |
|---|---|---|---|---|---|---|---|---|
| R-01 | a user retrieves another team's documents | 5 | 3 | 15 | C-01;C-08 | 5 | mitigate | no |
| R-02 | personal data is embedded and later surfaced in answers | 5 | 3 | 15 | C-02 | 10 | mitigate | yes: scrub misses free-text names in scanned PDFs |
| R-03 | a prompt edit bypasses review and weakens refusals | 4 | 3 | 12 | C-03 | 4 | mitigate | no |
| R-04 | the assistant answers confidently without a source | 3 | 4 | 12 | C-04;C-07 | 9 | mitigate | yes: citation check not yet run on streaming answers |
| R-05 | token spend spikes from a looping client | 3 | 3 | 9 | C-05 | 3 | mitigate | no |
| R-06 | a provider silently swaps the model version | 4 | 2 | 8 | C-06 | 8 | accept | yes: no provider change notice feed |

## point-6-lifecycle-changes
AUTO: POLICIES.md (change management policy)
- P1. Change management
- P2. Access control
- P3. Data handling
- P4. Incident response
Relevant changes through the lifecycle: {{J.LIFECYCLE_CHANGES}}

## point-7-standards-applied
AUTO: CROSSWALK.tsv coverage
rows 14; ai_rmf_function non-blank 5; ai_rmf_subcategory non-blank 14; csf2 non-blank 8; iso42001_clause non-blank 4; eu_ai_act_article non-blank 0; owasp_llm non-blank 6
Harmonised standards and other specifications applied: {{J.STANDARDS_APPLIED}}

## point-8-declaration-of-conformity
JUDGMENT: owner
Copy or reference of the EU declaration: {{J.DECLARATION}}

## point-9-post-market-monitoring
JUDGMENT: owner
Post-market monitoring system and plan: {{J.POST_MARKET}}
