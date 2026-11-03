import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOC2_ID = re.compile(r"(CC|A|C|PI|P)\d+(\.\d+)?")


def load(name):
    with open(ROOT / name, newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def crosswalk_soc2_ids(rows):
    return {x for r in rows for x in r["soc2"].split(";") if x}


def soc2_rows(rows):
    return [r for r in rows if r["standard"] == "AICPA SOC 2" and SOC2_ID.fullmatch(r["section_id"])]


def missing_ids(cw_ids, rows):
    have = {r["section_id"] for r in soc2_rows(rows)}
    return sorted(cw_ids - have)


def test_every_crosswalk_soc2_id_has_standards_row():
    ids = crosswalk_soc2_ids(load("CROSSWALK.tsv"))
    assert len(ids) >= 10  # empty-input guard
    assert missing_ids(ids, load("STANDARDS.tsv")) == []


def test_planted_crosswalk_id_is_caught():
    ids = crosswalk_soc2_ids(load("CROSSWALK.tsv")) | {"CC99.9"}
    assert missing_ids(ids, load("STANDARDS.tsv")) == ["CC99.9"]


def test_soc2_rows_are_structure_only_and_short():
    rows = soc2_rows(load("STANDARDS.tsv"))
    assert len(rows) >= 10
    for r in rows:
        assert r["fetched"] == "structure-only", r["section_id"]
        assert len(r["section_title"]) <= 50, r["section_id"]
        assert len(r["required_fields"]) <= 50, r["section_id"]


def annex_status(rows):
    """Return (eurlex_count, fetch_failed_ids, bad_ids) for numbered Annex IV rows."""
    ann = [r for r in rows if r["standard"] == "EU AI Act Annex IV" and r["section_id"].isdigit()]
    ok = [r for r in ann if "eur-lex.europa.eu" in r["source_url"]]
    failed = [r["section_id"] for r in ann if r not in ok and "FETCH-FAILED" in r["required_fields"]]
    bad = [r["section_id"] for r in ann if r not in ok and "FETCH-FAILED" not in r["required_fields"]]
    return len(ok), failed, bad, len(ann)


def test_annex_iv_rows_eurlex_or_reported_fetch_failed():
    ok, failed, bad, total = annex_status(load("STANDARDS.tsv"))
    assert total == 9
    assert bad == [], "mirror row without FETCH-FAILED marker: %s" % bad
    assert ok + len(failed) == 9


def test_planted_unmarked_mirror_row_is_caught():
    rows = load("STANDARDS.tsv")
    for r in rows:
        if r["standard"] == "EU AI Act Annex IV" and r["section_id"] == "1":
            r["source_url"] = "https://artificialintelligenceact.eu/annex/4/"
            r["required_fields"] = "x"
    assert "1" in annex_status(rows)[2]
