# OWASP LLM Top 10 2025 coverage (synthetic demo)

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
