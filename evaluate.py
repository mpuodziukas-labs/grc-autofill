#!/usr/bin/env python3
"""Run every tests/test_*.py function with the standard library only (no pytest needed).

Each test is a function named test_*, run once, or once per value of a @pytest.mark.parametrize mark;
a true skipif mark skips it. A test passes when it returns without raising.
Last line: "evaluate: N/N tests pass" and rc 0, or "evaluate: RED k/N tests pass" and rc 1.
"""
import importlib.util
import pathlib
import sys
import traceback

HERE = pathlib.Path(__file__).resolve().parent


def main():
    sys.path.insert(0, str(HERE))
    sys.path.insert(0, str(HERE / "tests"))
    p = n = 0
    for f in sorted((HERE / "tests").glob("test_*.py")):
        spec = importlib.util.spec_from_file_location(f.stem, f)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception:
            n += 1
            print("FAIL %s (import)" % f.name)
            traceback.print_exc(limit=2)
            continue
        for name in sorted(k for k in vars(mod) if k.startswith("test_") and callable(getattr(mod, k))):
            fn = getattr(mod, name)
            marks = getattr(fn, "pytestmark", [])
            if any(m.name == "skipif" and m.args and m.args[0] for m in marks):
                print("SKIP %s::%s" % (f.name, name))
                continue
            # a @pytest.mark.parametrize("arg", values) test runs once per value
            calls = [((), "")]
            for m in marks:
                if m.name == "parametrize":
                    calls = [((v,), "[%s]" % v) for v in m.args[1]]
            for args, tag in calls:
                n += 1
                try:
                    fn(*args)
                    p += 1
                except Exception as e:
                    print("FAIL %s::%s%s %s: %s" % (f.name, name, tag, type(e).__name__, str(e)[:200]))
    if n and p == n:
        print("evaluate: %d/%d tests pass" % (p, n))
        return 0
    print("evaluate: RED %d/%d tests pass" % (p, n))
    return 1


if __name__ == "__main__":
    sys.exit(main())
