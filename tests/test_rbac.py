import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(*args):
    p = subprocess.run([sys.executable, "rbac.py", *args], cwd=ROOT, capture_output=True, text=True)
    return p.returncode, p.stdout.strip().splitlines()


def test_selftest_counts():
    rc, out = run("--selftest")
    m = re.fullmatch(r"rbac selftest (\d+)/(\d+)", out[-1])
    assert rc == 0 and m and m.group(1) == m.group(2) and int(m.group(2)) >= 12


def test_viewer_reads_but_cannot_approve():
    assert run("check", "viewer", "read_report")[0] == 0
    assert run("check", "viewer", "approve_report", "--author", "a", "--actor", "b")[0] == 1


def test_deny_by_default_unknown_role_and_action():
    assert run("check", "intern", "read_report")[0] == 1
    assert run("check", "admin", "delete_everything")[0] == 1


def test_separation_of_duties():
    assert run("check", "approver", "approve_report", "--author", "alice", "--actor", "alice")[0] == 1
    assert run("check", "approver", "approve_report", "--author", "alice", "--actor", "bob")[0] == 0
    assert run("check", "approver", "approve_report")[0] == 1


def test_audit_log_records_reason():
    with tempfile.TemporaryDirectory() as d:
        log = Path(d) / "audit.jsonl"
        run("check", "viewer", "change_rules", "--audit-log", str(log))
        run("check", "analyst", "edit_judgment", "--audit-log", str(log))
        rows = [json.loads(x) for x in log.read_text().splitlines()]
    assert [r["allowed"] for r in rows] == [False, True]
    assert all(r["reason"] for r in rows)


def test_policy_has_no_wildcards():
    pol = json.loads((ROOT / "rbac-policy.json").read_text())
    assert pol["roles"] and all("*" not in a for acts in pol["roles"].values() for a in acts)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    ok = 0
    for t in tests:
        try:
            t()
            ok += 1
        except Exception as e:
            print("FAIL " + t.__name__ + " " + repr(e))
    print("tests %d/%d" % (ok, len(tests)))
    sys.exit(0 if ok == len(tests) else 1)
