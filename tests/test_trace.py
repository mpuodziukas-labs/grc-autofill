import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(*args):
    p = subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True)
    return p.returncode, p.stdout.strip().splitlines()


def test_trace_selftest():
    rc, out = run("trace.py", "--selftest")
    m = re.fullmatch(r"trace selftest (\d+)/(\d+)", out[-1])
    assert rc == 0 and m and m.group(1) == m.group(2) and int(m.group(2)) >= 10


def test_trace_check():
    rc, out = run("trace.py", "check")
    m = re.fullmatch(r"trace: (\d+)/(\d+) rows verify", out[-1])
    assert rc == 0 and m and m.group(1) == m.group(2) and int(m.group(2)) >= 20


def test_trace_escalate_is_offline_and_deterministic():
    rc, out = run("trace.py", "escalate", "--findings", "examples/findings.json", "--out", "examples/escalate-out")
    m = re.fullmatch(r"escalate: (\d+) issues from (\d+) findings", out[-1])
    assert rc == 0 and m and int(m.group(1)) >= 1 and m.group(2) == "7"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    ok = 0
    for t in tests:
        try:
            t()
            ok += 1
        except AssertionError:
            print("FAIL " + t.__name__)
    print("tests %d/%d" % (ok, len(tests)))
    sys.exit(0 if ok == len(tests) else 1)
