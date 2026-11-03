#!/usr/bin/env python3
"""Run every tests/test_*.py function with the standard library only (no pytest needed).

Each test is a zero-argument function named test_*. A test passes when it returns without raising.
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
            n += 1
            try:
                getattr(mod, name)()
                p += 1
            except Exception as e:
                print("FAIL %s::%s %s: %s" % (f.name, name, type(e).__name__, str(e)[:200]))
    if n and p == n:
        print("evaluate: %d/%d tests pass" % (p, n))
        return 0
    print("evaluate: RED %d/%d tests pass" % (p, n))
    return 1


if __name__ == "__main__":
    sys.exit(main())
