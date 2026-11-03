# Model Card - {{J.MODEL_NAME}}

Report date: {{REPORT_DATE}}. Sections follow Mitchell et al. 4.1-4.5 (fetched) and 4.6-4.9 (structure only).

## model-details
JUDGMENT: owner
Developer, version, type, license, contact: {{J.MODEL_DETAILS}}

## intended-use
JUDGMENT: owner
Primary uses, users, out-of-scope uses: {{J.INTENDED_USE}}

## factors
JUDGMENT: owner
Relevant groups, instrumentation and environment: {{J.FACTORS}}

## metrics
JUDGMENT: owner
Measures and decision thresholds: {{J.METRICS}}

## evaluation-data
JUDGMENT: owner
Datasets, motivation, preprocessing: {{J.EVAL_DATA}}

## training-data
JUDGMENT: owner
Training data description: {{J.TRAINING_DATA}}

## quantitative-analyses
AUTO: GUARDS.tsv last lint results (automated check results, not model benchmark scores)
{{GUARD_STATS}}
Model performance results by factor: {{J.QUANT_RESULTS}}

## ethical-considerations
AUTO: RISK-REGISTER.tsv
{{RISK_TABLE}}
Owner assessment of ethical risks: {{J.ETHICS}}

## security-considerations
AUTO: OWASP LLM Top 10 2025 coverage from COVERAGE.md
{{OWASP_TABLE}}

## caveats-and-recommendations
JUDGMENT: owner
Known limitations and recommendations: {{J.CAVEATS}}
