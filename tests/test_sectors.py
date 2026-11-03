import csv
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKS = {
    "hipaa-security": "hipaa-security-crosswalk",
    "sr-11-7": "sr11-7-model-risk",
}
COLS = ["id", "title", "source_url", "quoted_fragment", "fetched", "maps_to", "edge"]


def load(path):
    with open(path, newline="") as f:
        r = csv.DictReader(f, delimiter="\t")
        assert r.fieldnames == COLS, r.fieldnames
        return list(r)


def crosswalk_ids():
    with open(ROOT / "CROSSWALK.tsv", newline="") as f:
        return {r["control_id"] for r in csv.DictReader(f, delimiter="\t")}


def problems(rows, ids):
    """Return a list of defects; empty list means the pack is clean."""
    bad = []
    if not rows:
        bad.append("empty pack")
    seen = set()
    for r in rows:
        i = r["id"]
        if not i or i in seen:
            bad.append("%s: missing or duplicate id" % i)
        seen.add(i)
        if not r["source_url"].startswith("https://"):
            bad.append("%s: no source_url" % i)
        if r["fetched"] not in ("yes", "no"):
            bad.append("%s: fetched must be yes or no" % i)
        if r["fetched"] == "yes" and not r["quoted_fragment"].strip():
            bad.append("%s: fetched row has no quoted fragment" % i)
        if r["fetched"] == "no" and r["quoted_fragment"].strip():
            bad.append("%s: unfetched row must not carry a quote" % i)
        if r["edge"] not in ("GROUNDED", "INFERRED"):
            bad.append("%s: edge must be GROUNDED or INFERRED" % i)
        if r["edge"] == "GROUNDED" and r["fetched"] != "yes":
            bad.append("%s: GROUNDED edge needs a fetched row" % i)
        for c in [x for x in r["maps_to"].split(";") if x.strip()]:
            if c.strip() not in ids:
                bad.append("%s: unknown control id %s" % (i, c.strip()))
    return bad


def test_packs_clean():
    ids = crosswalk_ids()
    for name in PACKS:
        rows = load(ROOT / "sectors" / (name + ".tsv"))
        assert len(rows) >= 8, name
        assert problems(rows, ids) == [], (name, problems(rows, ids))


def test_hipaa_rows_cover_four_sections():
    rows = load(ROOT / "sectors" / "hipaa-security.tsv")
    for sec in ("164.308", "164.310", "164.312", "164.316"):
        assert any(r["id"].startswith(sec) for r in rows), sec


def test_sr117_rows_cover_pillars():
    text = " ".join(r["title"].lower() for r in load(ROOT / "sectors" / "sr-11-7.tsv"))
    for word in ("development", "conceptual soundness", "ongoing monitoring", "outcomes analysis",
                 "governance", "inventory"):
        assert word in text, word


def test_planted_bad_rows_are_caught():
    ids = crosswalk_ids()
    rows = load(ROOT / "sectors" / "hipaa-security.tsv")
    base = dict(rows[0])
    for field, val, frag in (
        ("maps_to", "C-99", "unknown control id"),
        ("source_url", "", "no source_url"),
        ("quoted_fragment", "", "no quoted fragment"),
        ("fetched", "no", "must not carry a quote"),
        ("edge", "MAYBE", "edge must be"),
    ):
        bad = dict(base)
        bad["fetched"] = "yes" if field != "fetched" else "no"
        bad["quoted_fragment"] = base["quoted_fragment"] or "x"
        bad[field] = val
        found = problems([bad], ids)
        assert any(frag in p for p in found), (field, found)


def test_templates_fill_with_zero_unresolved_auto():
    for tpl in PACKS.values():
        with tempfile.TemporaryDirectory() as od:
            p = subprocess.run(
                [sys.executable, "grc_autofill.py", "--evidence", "examples/evidence", tpl,
                 "--out", od, "--date", "2026-11-02"],
                cwd=ROOT, capture_output=True, text=True)
            assert p.returncode == 0, p.stderr
            assert "unknown=0 missing=0" in p.stdout, p.stdout
            out = (Path(od) / (tpl + "-2026-11-02.md")).read_text()
            assert not re.search(r"\{\{(?!J\.)", out), "unresolved AUTO field"
            assert "draft for assessor review" in out
            low = out.lower()
            for banned in ("audit-ready", "is compliant", "certified"):
                assert banned not in low, banned


def test_templates_and_tsvs_ascii():
    for name in list(PACKS) + list(PACKS.values()):
        p = ROOT / ("sectors/%s.tsv" % name if name in PACKS else "templates/%s.md" % name)
        assert all(ord(c) < 128 for c in p.read_text()), p
