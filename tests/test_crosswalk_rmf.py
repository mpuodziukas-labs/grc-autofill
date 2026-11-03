import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ID = re.compile(r"(GOVERN|MAP|MEASURE|MANAGE) \d+\.\d+")


def valid_ids():
    with open(ROOT / "STANDARDS.tsv", newline="") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    return {r["section_id"] for r in rows if r["standard"].startswith("NIST AI RMF 1.0 Playbook") and ID.fullmatch(r["section_id"])}


def crosswalk():
    with open(ROOT / "CROSSWALK.tsv", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def bad_ids(rows, valid):
    return [(r["control_id"], i) for r in rows for i in r["ai_rmf_subcategory"].split(";") if i.strip() and i.strip() not in valid]


def test_known_ids_loaded():
    assert len(valid_ids()) >= 50


def test_every_filled_id_exists_in_standards():
    assert bad_ids(crosswalk(), valid_ids()) == []


def test_planted_bogus_id_is_caught():
    rows = crosswalk() + [{"control_id": "X", "ai_rmf_subcategory": "MAP 3.5;MAP 99.9"}]
    assert bad_ids(rows, valid_ids()) == [("X", "MAP 99.9")]


def test_filled_and_blank_counts():
    rows = crosswalk()
    filled = [r for r in rows if r["ai_rmf_subcategory"].strip()]
    assert len(rows) == 14 and len(filled) >= 8


def test_every_filled_row_is_tagged():
    for r in crosswalk():
        if r["ai_rmf_subcategory"].strip():
            assert re.search(r"ai_rmf_subcategory (GROUNDED|INFERRED)", r["basis"]), r["control_id"]


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
