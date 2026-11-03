import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(*args):
    p = subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True)
    return p.returncode, p.stdout.strip().splitlines()


def test_grc_autofill_selftest():
    rc, out = run("grc_autofill.py", "--selftest")
    m = re.fullmatch(r"grc-autofill selftest (\d+)/(\d+)", out[-1])
    assert rc == 0 and m and m.group(1) == m.group(2)


def test_claimdiode_selftest():
    rc, out = run("claimdiode.py", "--selftest")
    m = re.fullmatch(r"claimdiode selftest (\d+)/(\d+)", out[-1])
    assert rc == 0 and m and m.group(1) == m.group(2)


def test_claimdiode_demo_tamper_is_caught():
    rc, out = run("claimdiode.py", "demo")
    assert rc == 0 and out[-1] == "demo: 2/2 expectations met"
    assert "demo: after tamper: 7 of 12 claims INVALIDATED, verify exit 1" in out


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
