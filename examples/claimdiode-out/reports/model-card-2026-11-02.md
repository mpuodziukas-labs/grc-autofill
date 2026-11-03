# Model Card - {{J.MODEL_NAME}}

Report date: 2026-11-02. Sections follow Mitchell et al. 4.1-4.5 (fetched) and 4.6-4.9 (structure only).

## model-details
JUDGMENT: owner
Developer, version, type, license, contact: {{J.MODEL_DETAILS}}

Claims bound to evidence (claimdiode):
- Assessed build acme-rag-assistant 1.4.2 is identified by 4 file digests (manifest sha256 910c22ca8a5c). [claim CD-01 | sha256:d3ece036794de76f | AUTO | HIGH | ev:EV-MODEL]

## intended-use
JUDGMENT: owner
Primary uses, users, out-of-scope uses: {{J.INTENDED_USE}}

## factors
JUDGMENT: owner
Relevant groups, instrumentation and environment: {{J.FACTORS}}

## metrics
JUDGMENT: owner
Measures and decision thresholds: {{J.METRICS}}

Claims bound to evidence (claimdiode):
- 4 of 4 harmful-request probes were refused. [claim CD-03 | sha256:3586ef19e00fb390 | AUTO | HIGH | ev:EV-MODEL,EV-REF]

## evaluation-data
JUDGMENT: owner
Datasets, motivation, preprocessing: {{J.EVAL_DATA}}

## training-data
JUDGMENT: owner
Training data description: {{J.TRAINING_DATA}}

## quantitative-analyses
AUTO: GUARDS.tsv last lint results (automated check results, not model benchmark scores)
guards 6; with selftest 5; last lint rc 0: 4; rc non-zero: 1; UNKNOWN: 1
Model performance results by factor: {{J.QUANT_RESULTS}}

## ethical-considerations
AUTO: RISK-REGISTER.tsv
| Risk | What could go wrong | Impact | Likelihood | Inherent | Controls | Residual | Treatment | Open gap |
|---|---|---|---|---|---|---|---|---|
| R-01 | a user retrieves another team's documents | 5 | 3 | 15 | C-01;C-08 | 5 | mitigate | no |
| R-02 | personal data is embedded and later surfaced in answers | 5 | 3 | 15 | C-02 | 10 | mitigate | yes: scrub misses free-text names in scanned PDFs |
| R-03 | a prompt edit bypasses review and weakens refusals | 4 | 3 | 12 | C-03 | 4 | mitigate | no |
| R-04 | the assistant answers confidently without a source | 3 | 4 | 12 | C-04;C-07 | 9 | mitigate | yes: citation check not yet run on streaming answers |
| R-05 | token spend spikes from a looping client | 3 | 3 | 9 | C-05 | 3 | mitigate | no |
| R-06 | a provider silently swaps the model version | 4 | 2 | 8 | C-06 | 8 | accept | yes: no provider change notice feed |
Owner assessment of ethical risks: {{J.ETHICS}}

## security-considerations
AUTO: OWASP LLM Top 10 2025 coverage from COVERAGE.md
| Id | Title | Runnable evidence | Status |
|---|---|---|---|
| LLM01 | Prompt Injection | make verify-prompts | PARTIAL |
| LLM02 | Sensitive Information Disclosure | make verify-scrub | COVERED |
| LLM03 | Supply Chain | make verify-models | COVERED |
| LLM04 | Data and Model Poisoning | none yet | GAP |
| LLM05 | Improper Output Handling | make verify-cites | PARTIAL |
| LLM06 | Excessive Agency | not applicable, no tools | N/A |
| LLM07 | System Prompt Leakage | make verify-prompts | PARTIAL |
| LLM08 | Vector and Embedding Weaknesses | make verify-acl | COVERED |
| LLM09 | Misinformation | make verify-queue | PARTIAL |
| LLM10 | Unbounded Consumption | make verify-limits | COVERED |

Claims bound to evidence (claimdiode):
- The system-prompt canary leaked in 0 of 4 injection probes. [claim CD-02 | sha256:751faeb0e0e799e2 | AUTO | LOW | ev:EV-MODEL,EV-INJ]

## caveats-and-recommendations
JUDGMENT: owner
Known limitations and recommendations: {{J.CAVEATS}}
