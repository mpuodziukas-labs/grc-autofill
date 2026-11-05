import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RULES = ["R1", "R2", "R3", "R4"]
RED = {
    "R1": "write-all.yml",
    "R2": "unpinned-action.yml",
    "R3": "prt-head-checkout.yml",
    "R4": "event-in-run.yml",
}
ALLOWED_URLS = {
    "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf",
    "https://slsa.dev/spec/v1.0/requirements",
}

needs_conftest = pytest.mark.skipif(shutil.which("conftest") is None, reason="conftest not installed")


def failures(path):
    p = subprocess.run(
        ["conftest", "test", "-p", "policy/ci", "--output", "json", str(path)],
        cwd=ROOT, capture_output=True, text=True,
    )
    data = json.loads(p.stdout)
    msgs = [f["msg"] for d in data for f in (d.get("failures") or [])]
    return p.returncode, msgs


@needs_conftest
@pytest.mark.parametrize("rule", RULES)
def test_red_fixture_fails_only_its_rule(rule):
    rc, msgs = failures(ROOT / "fixtures/workflows" / RED[rule])
    assert rc != 0
    assert msgs and all(m.startswith(rule + " ") for m in msgs), msgs


@needs_conftest
@pytest.mark.parametrize("rule", RULES)
def test_green_fixture_passes(rule):
    rc, msgs = failures(ROOT / "fixtures/workflows/good" / RED[rule])
    assert rc == 0 and msgs == []


@needs_conftest
def test_repo_ci_workflow_is_clean():
    rc, msgs = failures(ROOT / ".github/workflows/ci.yml")
    assert rc == 0 and msgs == []


def test_evidence_rows_cover_every_rule_with_grounded_or_inferred_labels():
    ev = json.loads((ROOT / "evidence/ci-controls.json").read_text())
    assert [r["rule"] for r in ev["rows"]] == RULES
    rego = (ROOT / "policy/ci/workflow.rego").read_text()
    for r in ev["rows"]:
        assert r["rule"] + " " in rego
        assert (ROOT / r["fixture_red"]).is_file() and (ROOT / r["fixture_green"]).is_file()
        assert r["controls"]
        for c in r["controls"]:
            assert c["label"] in {"GROUNDED", "INFERRED"}
            assert c["source_url"] in ALLOWED_URLS
            assert c["id"].startswith(("SSDF ", "SLSA "))
