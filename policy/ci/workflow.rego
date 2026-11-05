package main

import rego.v1

# R1: write scopes granted at workflow level.
deny contains msg if {
	p := input.permissions
	p == "write-all"
	msg := "R1 workflow-level permissions: write-all"
}

deny contains msg if {
	some scope, level in input.permissions
	level == "write"
	msg := sprintf("R1 workflow-level write scope: %s", [scope])
}

# R2: third-party action not pinned to a 40-character commit sha.
# Third party = any owner other than actions or github. Local (./) and docker:// refs are skipped.
first_party(ref) if startswith(ref, "actions/")

first_party(ref) if startswith(ref, "github/")

first_party(ref) if startswith(ref, "./")

first_party(ref) if startswith(ref, "docker://")

deny contains msg if {
	some job_id, job in input.jobs
	some step in job.steps
	ref := step.uses
	not first_party(ref)
	not regex.match(`@[0-9a-f]{40}$`, ref)
	msg := sprintf("R2 unpinned third-party action in job %s: %s", [job_id, ref])
}

# R3: pull_request_target combined with checkout of the PR head.
# YAML 1.1 parsers read the bare key `on` as boolean true, so accept both spellings.
triggers := object.get(input, "on", object.get(input, "true", {}))

has_prt if triggers == "pull_request_target"

has_prt if "pull_request_target" in triggers

has_prt if triggers.pull_request_target

head_ref(ref) if contains(ref, "github.event.pull_request.head")

head_ref(ref) if contains(ref, "github.head_ref")

deny contains msg if {
	has_prt
	some job_id, job in input.jobs
	some step in job.steps
	startswith(step.uses, "actions/checkout")
	head_ref(sprintf("%v", [step["with"].ref]))
	msg := sprintf("R3 pull_request_target checks out the PR head in job %s", [job_id])
}

# R4: github.event.* expanded inside a run script.
deny contains msg if {
	some job_id, job in input.jobs
	some step in job.steps
	contains(step.run, "${{ github.event.")
	msg := sprintf("R4 github.event expanded in run script, job %s", [job_id])
}
