# NIST AI RMF 1.0 Profile - {{J.SYSTEM_NAME}}

Report date: 2026-11-02. Functions: GOVERN, MAP, MEASURE, MANAGE. Subcategory text is in STANDARDS.tsv where fetched.

## use-case-and-context
AUTO: POLICIES.md Scope line
Scope: the acme-rag-assistant service, its vector index, prompt templates and the staff who operate it.
AI system purpose, users and affected parties: {{J.USE_CASE}}

## functions-coverage
AUTO: GUARDS.tsv tags column (NIST: tags), counted per function
| AI RMF function | Guard count | First guards |
|---|---|---|
| GOVERN | 2 | g-acl, g-prompt-pin |
| MANAGE | 1 | g-scrub |
| MEASURE | 2 | g-cites, g-latency |

## crosswalk
AUTO: CROSSWALK.tsv
rows 14; ai_rmf_function non-blank 5; ai_rmf_subcategory non-blank 14; csf2 non-blank 8; iso42001_clause non-blank 4; eu_ai_act_article non-blank 0; owasp_llm non-blank 6

Subcategory mapping is blank unless a grounded source supplied it; owner fills the rest.

## govern
AUTO: POLICIES.md
- P1. Change management
- P2. Access control
- P3. Data handling
- P4. Incident response
Accountability, roles and culture: {{J.GOVERN_NARRATIVE}}

## map
JUDGMENT: owner
Context, intended purpose, impacts, third-party risk. Owner narrative: {{J.MAP_NARRATIVE}}

Claims bound to evidence (claimdiode):
- Prompt-injection testing is mapped to the OWASP LLM list by title match; the mapping is the author inference. [claim CD-08 | sha256:57be143ccf37adcd | INFERRED | LOW | ev:EV-CTRL]

## measure
AUTO: guard stats from GUARDS.tsv
guards 6; with selftest 5; last lint rc 0: 4; rc non-zero: 1; UNKNOWN: 1
Metrics and TEVV method rationale: {{J.MEASURE_NARRATIVE}}

Claims bound to evidence (claimdiode):
- Synthetic personal data was echoed in 0 of 3 probes. [claim CD-04 | sha256:ae4b1f2af1a09b44 | AUTO | LOW | ev:EV-MODEL,EV-PII]
- 3 of 3 structured-output probes matched the answer schema. [claim CD-05 | sha256:2d8c370006da9f60 | AUTO | HIGH | ev:EV-MODEL,EV-SCH]

## manage
AUTO: RISK-REGISTER.tsv
| Risk | What could go wrong | Impact | Likelihood | Inherent | Controls | Residual | Treatment | Open gap |
|---|---|---|---|---|---|---|---|---|
| R-01 | a user retrieves another team's documents | 5 | 3 | 15 | C-01;C-08 | 5 | mitigate | no |
| R-02 | personal data is embedded and later surfaced in answers | 5 | 3 | 15 | C-02 | 10 | mitigate | yes: scrub misses free-text names in scanned PDFs |
| R-03 | a prompt edit bypasses review and weakens refusals | 4 | 3 | 12 | C-03 | 4 | mitigate | no |
| R-04 | the assistant answers confidently without a source | 3 | 4 | 12 | C-04;C-07 | 9 | mitigate | yes: citation check not yet run on streaming answers |
| R-05 | token spend spikes from a looping client | 3 | 3 | 9 | C-05 | 3 | mitigate | no |
| R-06 | a provider silently swaps the model version | 4 | 2 | 8 | C-06 | 8 | accept | yes: no provider change notice feed |
Prioritization and response decisions: {{J.MANAGE_NARRATIVE}}

Claims bound to evidence (claimdiode):
- Owner judgment: controls without a receipt stay open items until the next review. [claim CD-11 | sha256:57be143ccf37adcd | JUDGMENT | MEDIUM | ev:EV-CTRL]

