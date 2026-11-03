# Acme RAG Assistant policies (synthetic demo)

Scope: the acme-rag-assistant service, its vector index, prompt templates and the staff who operate it.

## P1. Change management
All prompt, model and index changes go through review and a recorded release.

## P2. Access control
Retrieval honors the caller's group membership; no shared service accounts.

## P3. Data handling
Personal data is scrubbed before indexing; logs are redacted and kept 90 days.

## P4. Incident response
Wrong or unsafe answers are triaged within one business day.
