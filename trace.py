#!/usr/bin/env python3
"""trace: code-to-control matrix, its renderer, and offline Jira-shaped escalation. stdlib only, no network.

  trace.py check                      every matrix row names a real function, a well-formed control id and a real test
  trace.py render                     write TRACE-MATRIX.md from TRACE-MATRIX.tsv (deterministic)
  trace.py escalate --findings F.json --out DIR      or  --verify-log FILE (claimdiode verify output)
  trace.py --selftest                 planted defects must be caught
"""
import argparse
import ast
import contextlib
import csv
import io
import json
import os
import re
import shutil
import sys
import tempfile

KIT = os.path.dirname(os.path.abspath(__file__))
MODULES = ("grc_autofill.py", "claimdiode.py")
COLS = ["module", "function", "control_framework", "control_id", "control_title", "requirement_text_or_ref",
        "basis", "source_url", "test_that_enforces"]
ESC_COLS = ["rule_id", "trigger", "severity", "jira_priority", "labels", "owner_role", "sla_hours"]
FRAMEWORKS = {  # name -> control id shape
    "SOC 2 TSC 2017": r"(?:CC[1-9]\.\d|A1\.[1-3]|C1\.[12]|PI1\.[1-5]|P[1-8]\.\d)",
    "EU AI Act": r"(?:Art\. \d{1,3}|Annex [IVX]{1,5})",
    "ISO/IEC 42001": r"(?:(?:[4-9]|10)(?:\.\d{1,2}){0,2}|A\.\d{1,2}(?:\.\d{1,2})?)",
    "NIST AI RMF": r"(?:GOVERN|MAP|MEASURE|MANAGE) [1-6]\.\d{1,2}",
}
BASES = ("GROUNDED", "INFERRED")
SEVERITY = ("critical", "high", "medium", "low")
PRIORITY = ("Highest", "High", "Medium", "Low", "Lowest")
# trigger -> (file the trigger word must appear in, the word, module, function that enforces it)
TRIGGERS = {
    "claim_invalidated": ("claimdiode.py", "INVALIDATED", "claimdiode.py", "verify"),
    "chain_broken": ("claimdiode.py", "CHAIN_BROKEN", "claimdiode.py", "chain_check"),
    "digest_mismatch": ("claimdiode.py", "DIGEST_MISMATCH", "claimdiode.py", "verify"),
    "rule_fail": ("claimdiode.py", "FAIL", "claimdiode.py", "rule_status"),
    "confidence_low": ("claimdiode.py", "LOW", "claimdiode.py", "bound"),
    "evidence_stale": ("claimdiode.py", "STALE", "claimdiode.py", "is_stale"),
    "rule_toothless": ("claimdiode.py", "TOOTHLESS", "claimdiode.py", "teeth"),
    "evidence_missing": ("grc_autofill.py", "NO-EVIDENCE", "grc_autofill.py", "_ev_check"),
    "malformed_evidence": ("grc_autofill.py", "MALFORMED", "grc_autofill.py", "_read_tsv"),
}
MIRROR_NOTE = ("EU AI Act article text was read on 2026-11-02 from a non-primary mirror "
               "(artificialintelligenceact.eu); verify against the Official Journal before relying on it.")


def p(root, *a):
    return os.path.join(root, *a)


def read_text(path):
    try:
        with open(path) as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


def write_tsv(path, cols, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_NONE, quotechar=None)
        w.writerow(cols)
        w.writerows([[r[c] for c in cols] for r in rows])


def load_tsv(path, cols):
    """Return (rows, errors). A missing file, wrong header or ragged row is an error, never an empty pass."""
    try:
        with open(path, newline="") as f:
            lines = list(csv.reader(f, delimiter="\t", quoting=csv.QUOTE_NONE))
    except (OSError, UnicodeDecodeError, csv.Error):
        return [], ["%s: unreadable" % os.path.basename(path)]
    if not lines or lines[0] != cols:
        return [], ["%s: header is not %s" % (os.path.basename(path), ",".join(cols))]
    rows, errs = [], []
    for n, ln in enumerate(lines[1:], 2):
        if len(ln) != len(cols):
            errs.append("%s line %d: %d cells, want %d" % (os.path.basename(path), n, len(ln), len(cols)))
        else:
            rows.append(dict(zip(cols, ln)))
    return rows, errs


def top_functions(src):
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return set()
    return set(n.name for n in tree.body if isinstance(n, ast.FunctionDef))


def case_names(root):
    """Names of selftest cases (guarded("...") in the two modules) and pytest-style tests."""
    names = set()
    for m in MODULES + ("trace.py",):
        t = read_text(p(root, m)) or ""
        names.update(re.findall(r'guarded\(\s*"((?:[^"\\]|\\.)*)"', t))
    tdir = p(root, "tests")
    for fn in sorted(os.listdir(tdir)) if os.path.isdir(tdir) else []:
        if fn.endswith(".py"):
            names.update(re.findall(r"(?m)^def (test_\w+)\(", read_text(p(tdir, fn)) or ""))
    return names


def row_errors(r, funcs, cases, seen):
    e = []
    if r["module"] not in MODULES:
        e.append("module %r is not one of %s" % (r["module"], ",".join(MODULES)))
    elif r["function"] not in funcs.get(r["module"], set()):
        e.append("function %s not found in %s" % (r["function"], r["module"]))
    fw = r["control_framework"]
    if fw not in FRAMEWORKS:
        e.append("unknown framework %r" % fw)
    elif not re.fullmatch(FRAMEWORKS[fw], r["control_id"]):
        e.append("control id %r is malformed for %s" % (r["control_id"], fw))
    if r["basis"] not in BASES:
        e.append("basis %r is not GROUNDED or INFERRED" % r["basis"])
    elif r["basis"] == "GROUNDED":
        if not r["source_url"].startswith("https://"):
            e.append("GROUNDED row has no https source_url")
        if not r["requirement_text_or_ref"].startswith('"'):
            e.append("GROUNDED row text is not a quotation")
    elif not r["requirement_text_or_ref"].startswith(("paraphrase:", "ref:")):
        e.append("INFERRED row text must start with paraphrase: or ref:")
    for c in COLS:
        if c != "source_url" and not r[c].strip():
            e.append("empty %s" % c)
    tests = [t for t in r["test_that_enforces"].split(";") if t.strip()]
    if not tests:
        e.append("no test named")
    for t in tests:
        if t not in cases:
            e.append("test %r does not exist" % t)
    if any(ord(ch) > 127 for ch in "".join(r.values())):
        e.append("non-ASCII character")
    key = (r["module"], r["function"], r["control_framework"], r["control_id"])
    if key in seen:
        e.append("duplicate row")
    seen.add(key)
    return e


def check_rows(rows, root):
    """Return (ok_row_count, error lines)."""
    if not rows:
        return 0, ["matrix has zero rows (an empty matrix is not a pass)"]
    funcs = {m: top_functions(read_text(p(root, m)) or "") for m in MODULES}
    cases, seen, ok, errs = case_names(root), set(), 0, []
    for n, r in enumerate(rows, 2):
        e = row_errors(r, funcs, cases, seen)
        ok += not e
        errs += ["TRACE-MATRIX.tsv line %d (%s %s): %s" % (n, r["module"], r["function"], x) for x in e]
    return ok, errs


def check_rules(rules, rows, root):
    errs, seen = [], set()
    if not rules:
        return ["ESCALATION.tsv has zero rules"]
    have = set((r["module"], r["function"]) for r in rows)
    for r in rules:
        rid, why = r["rule_id"], []
        if rid in seen:
            why.append("duplicate rule_id")
        seen.add(rid)
        t = TRIGGERS.get(r["trigger"])
        if t is None:
            why.append("trigger %r is not a known finding kind (rule can never match)" % r["trigger"])
        else:
            src = read_text(p(root, t[0])) or ""
            if t[1] not in src:
                why.append("trigger word %s no longer appears in %s (rule can never match)" % (t[1], t[0]))
            if (t[2], t[3]) not in have:
                why.append("no matrix row for %s::%s, issue would carry no control ids" % (t[2], t[3]))
        if r["severity"] not in SEVERITY:
            why.append("severity %r" % r["severity"])
        if r["jira_priority"] not in PRIORITY:
            why.append("jira_priority %r" % r["jira_priority"])
        if not r["sla_hours"].isdigit() or int(r["sla_hours"]) <= 0:
            why.append("sla_hours %r" % r["sla_hours"])
        if not r["labels"].strip() or not r["owner_role"].strip():
            why.append("labels and owner_role must be set")
        errs += ["ESCALATION.tsv %s: %s" % (rid, w) for w in why]
    return errs


def check_blueprint(root):
    """Every long double-quoted phrase in docs/BLUEPRINT.md must be the exact name of a selftest case."""
    t = read_text(p(root, "docs", "BLUEPRINT.md"))
    if t is None:
        return ["docs/BLUEPRINT.md: unreadable"]
    cites = re.findall(r'"([^"\n]{20,})"', t)
    cases = case_names(root)
    errs = ["docs/BLUEPRINT.md cites a test that does not exist: %r" % c for c in cites if c not in cases]
    return errs if cites else ["docs/BLUEPRINT.md cites no tests"]


def cmd_check(root):
    rows, e1 = load_tsv(p(root, "TRACE-MATRIX.tsv"), COLS)
    rules, e2 = load_tsv(p(root, "ESCALATION.tsv"), ESC_COLS)
    ok, e3 = check_rows(rows, root)
    errs = e1 + e2 + e3 + (check_rules(rules, rows, root) if rules else []) + check_blueprint(root)
    for e in errs:
        print("RED " + e)
    print("trace: %d/%d rows verify" % (ok, len(rows) + len(e1)))
    return 0 if not errs and rows and ok == len(rows) else 1


def idkey(s):
    return [(0, int(x), "") if x.isdigit() else (1, 0, x) for x in re.findall(r"\d+|\D+", s)]


def render(rows):
    g = sum(r["basis"] == "GROUNDED" for r in rows)
    out = ["# Trace matrix: code to control", "",
           "Source of truth: `TRACE-MATRIX.tsv`. This file is rendered by `python3 trace.py render` and is never edited by hand.",
           "%d rows. GROUNDED %d/%d (control text quoted from a fetched public source), INFERRED %d/%d (short paraphrase, "
           "not a quotation; verify before relying on it)." % (len(rows), g, len(rows), len(rows) - g, len(rows)), "",
           MIRROR_NOTE, "",
           "A row means: this function enforces something related to this requirement, and the named test fails if it stops. "
           "It is a mapping for engineers and reviewers. It is not a claim that any framework is satisfied.", ""]
    for fw in FRAMEWORKS:
        sub = sorted((r for r in rows if r["control_framework"] == fw),
                     key=lambda r: (idkey(r["control_id"]), r["module"], r["function"]))
        if not sub:
            continue
        out += ["## " + fw, "", "| Control | Title | Code | Basis | Requirement or reference | Enforcing test |",
                "|---|---|---|---|---|---|"]
        for r in sub:
            req = r["requirement_text_or_ref"] + (" [source](%s)" % r["source_url"] if r["source_url"] else "")
            cells = [r["control_id"], r["control_title"], "`%s::%s`" % (r["module"], r["function"]), r["basis"], req,
                     "<br>".join(r["test_that_enforces"].split(";"))]
            out.append("| " + " | ".join(c.replace("|", "/") for c in cells) + " |")
        out.append("")
    return "\n".join(out) + "\n"


def cmd_render(root):
    rows, errs = load_tsv(p(root, "TRACE-MATRIX.tsv"), COLS)
    if errs or not rows:
        print("render: matrix unreadable or empty")
        return 1
    with open(p(root, "TRACE-MATRIX.md"), "w", newline="") as f:
        f.write(render(rows))
    print("render: %d rows -> TRACE-MATRIX.md" % len(rows))
    return 0


VERIFY_RE = re.compile(r"^INVALIDATED (\S+) ([^/\s]+)/(\S+): (.*)$")


def parse_verify(text):
    """claimdiode verify output -> findings. Only INVALIDATED lines are read."""
    out = []
    for ln in text.splitlines():
        m = VERIFY_RE.match(ln.strip())
        if m:
            parts = [x.strip().split(" ", 1) for x in m.group(4).split(";")]
            out.append({"kind": "claim_invalidated", "claim_id": m.group(1), "report": m.group(2), "section": m.group(3),
                        "reasons": [x[0] for x in parts],
                        "evidence": sorted(set(x[1] for x in parts if len(x) > 1))})
    return out


def finding_kinds(f):
    return set([f["kind"]] + [x.lower() for x in f.get("reasons", [])])


def build_issues(findings, rules, rows, project="GRC"):
    """Return (issues {rule_id: jira payload}, count per rule, unrouted findings)."""
    by_rule = {r["rule_id"]: [] for r in rules}
    unrouted = []
    for f in findings:
        hit = [r for r in rules if r["trigger"] in finding_kinds(f)]
        for r in hit:
            by_rule[r["rule_id"]].append(f)
        if not hit:
            unrouted.append(f)
    issues = {}
    for r in rules:
        fs = by_rule[r["rule_id"]]
        if not fs:
            continue
        t = TRIGGERS[r["trigger"]]
        ctl = sorted(set("%s %s" % (x["control_framework"], x["control_id"]) for x in rows
                         if (x["module"], x["function"]) == (t[2], t[3])))
        lines = ["Rule %s fired on trigger %s (severity %s, owner role %s)." % (r["rule_id"], r["trigger"], r["severity"], r["owner_role"]),
                 "Respond within %s hours of creation (a policy input in ESCALATION.tsv, not a measured value)." % r["sla_hours"], "",
                 "Findings (%d):" % len(fs)]
        for f in fs:
            lines.append("- %s %s/%s: %s; evidence %s" % (f.get("claim_id", "-"), f.get("report", "-"), f.get("section", "-"),
                                                          ",".join(f.get("reasons", [])) or f["kind"],
                                                          ",".join(f.get("evidence", [])) or "-"))
        lines += ["", "Control ids (from TRACE-MATRIX.tsv, enforcing function %s::%s):" % (t[2], t[3])]
        lines += ["- " + c for c in ctl]
        lines += ["", "Mapping for review only. It is not a statement that any control is met or failed."]
        issues[r["rule_id"]] = {"fields": {
            "project": {"key": project}, "issuetype": {"name": "Task"},
            "summary": "[%s] %s: %d finding(s)" % (r["rule_id"], r["trigger"], len(fs)),
            "priority": {"name": r["jira_priority"]},
            "labels": sorted(set(r["labels"].split(",") + ["sla-%sh" % r["sla_hours"]])),
            "description": "\n".join(lines)}}
    return issues, {k: len(v) for k, v in by_rule.items()}, unrouted


def cmd_escalate(root, findings_path, verify_log, out_dir, project):
    rules, e1 = load_tsv(p(root, "ESCALATION.tsv"), ESC_COLS)
    rows, e2 = load_tsv(p(root, "TRACE-MATRIX.tsv"), COLS)
    if e1 or e2 or not rules or not rows:
        print("escalate: rules or matrix unreadable")
        return 2
    try:
        if verify_log:
            findings = parse_verify(read_text(verify_log) or "")
        else:
            with open(findings_path) as f:
                findings = json.load(f)
    except (OSError, ValueError, TypeError):
        print("escalate: findings input unreadable")
        return 2
    if not isinstance(findings, list) or any(not isinstance(f, dict) or not isinstance(f.get("kind"), str) for f in findings):
        print("escalate: findings must be a JSON list of objects with a kind")
        return 2
    issues, counts, unrouted = build_issues(findings, rules, rows, project)
    os.makedirs(out_dir, exist_ok=True)
    for rid, doc in sorted(issues.items()):
        with open(p(out_dir, rid + ".json"), "w", newline="") as f:
            f.write(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        print("issue %s %s %d finding(s) -> %s" % (rid, doc["fields"]["priority"]["name"], counts[rid], rid + ".json"))
    for f in unrouted:
        print("UNROUTED finding kind=%s claim=%s (no rule matches)" % (f["kind"], f.get("claim_id", "-")))
    print("escalate: %d issues from %d findings" % (len(issues), len(findings)))
    return 1 if unrouted else 0


def quiet(fn, *a, **k):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(*a, **k)
    return rc, buf.getvalue().strip().splitlines()


def selftest():
    res = []

    def chk(name, ok):
        res.append(bool(ok))
        print(("PASS " if ok else "FAIL ") + name)

    def guarded(name, fn):
        try:
            chk(name, fn())
        except Exception as e:  # a crash is a failed check, never a skip
            chk("%s (raised %s)" % (name, type(e).__name__), False)

    with tempfile.TemporaryDirectory() as tmp:
        def fresh(name):
            d = p(tmp, name)
            os.makedirs(d)
            for m in MODULES + ("trace.py", "TRACE-MATRIX.tsv", "ESCALATION.tsv"):
                shutil.copy(p(KIT, m), p(d, m))
            shutil.copytree(p(KIT, "tests"), p(d, "tests"))
            shutil.copytree(p(KIT, "docs"), p(d, "docs"))
            return d

        def mutate_matrix(name, fn):
            d = fresh(name)
            rows, _ = load_tsv(p(d, "TRACE-MATRIX.tsv"), COLS)
            fn(rows)
            write_tsv(p(d, "TRACE-MATRIX.tsv"), COLS, rows)
            return d

        def red(d):
            rc, out = quiet(cmd_check, d)
            return rc == 1 and any(x.startswith("RED ") for x in out)

        def good():
            d = fresh("good")
            rc, out = quiet(cmd_check, d)
            m = re.fullmatch(r"trace: (\d+)/(\d+) rows verify", out[-1])
            return rc == 0 and m and m.group(1) == m.group(2) and int(m.group(2)) >= 20
        guarded("good case: the shipped matrix and rules verify N/N (N >= 20)", good)

        def renamed():
            d = fresh("renamed")
            t = read_text(p(d, "claimdiode.py"))
            with open(p(d, "claimdiode.py"), "w") as f:
                f.write(t.replace("def chain_check(", "def chain_check_renamed(", 1))
            rc, out = quiet(cmd_check, d)
            return rc == 1 and any("function chain_check not found" in x for x in out)
        guarded("PLANTED renamed function: caught", renamed)

        def bad_id():
            def f(rows):
                rows[0]["control_id"] = "CC66.1x"
            return red(mutate_matrix("badid", f))
        guarded("PLANTED malformed control id: caught", bad_id)

        def no_url():
            def f(rows):
                next(r for r in rows if r["basis"] == "GROUNDED")["source_url"] = ""
            return red(mutate_matrix("nourl", f))
        guarded("PLANTED GROUNDED row with no url: caught", no_url)

        def no_quote():
            def f(rows):
                next(r for r in rows if r["basis"] == "GROUNDED")["requirement_text_or_ref"] = "paraphrase: invented"
            return red(mutate_matrix("noquote", f))
        guarded("PLANTED GROUNDED row whose text is not a quotation: caught", no_quote)

        def no_test():
            def f(rows):
                rows[0]["test_that_enforces"] = "no such selftest case"
            return red(mutate_matrix("notest", f))
        guarded("PLANTED missing test name: caught", no_test)

        def bad_basis():
            def f(rows):
                rows[0]["basis"] = "VERIFIED"
            return red(mutate_matrix("basis", f))
        guarded("PLANTED basis outside GROUNDED/INFERRED: caught", bad_basis)

        def dup():
            def f(rows):
                rows.append(dict(rows[0]))
            return red(mutate_matrix("dup", f))
        guarded("PLANTED duplicate row: caught", dup)

        def empty():
            d = mutate_matrix("empty", lambda rows: rows.clear())
            rc, out = quiet(cmd_check, d)
            return rc == 1 and out[-1] == "trace: 0/0 rows verify"
        guarded("PLANTED empty matrix: not a pass", empty)

        def dead_rule():
            d = fresh("deadrule")
            rules, _ = load_tsv(p(d, "ESCALATION.tsv"), ESC_COLS)
            rules[0]["trigger"] = "claimdiode_teleports"
            write_tsv(p(d, "ESCALATION.tsv"), ESC_COLS, rules)
            rc, out = quiet(cmd_check, d)
            return rc == 1 and any("can never match" in x for x in out)
        guarded("PLANTED rule whose trigger is unknown (never matches): caught", dead_rule)

        def dead_word():
            d = fresh("deadword")
            t = read_text(p(d, "claimdiode.py"))
            with open(p(d, "claimdiode.py"), "w") as f:
                f.write(t.replace("TOOTHLESS", "TOOTHY"))
            rc, out = quiet(cmd_check, d)
            return rc == 1 and any("TOOTHLESS no longer appears" in x for x in out)
        guarded("PLANTED trigger word gone from the source (never matches): caught", dead_word)

        def bad_sla():
            d = fresh("sla")
            rules, _ = load_tsv(p(d, "ESCALATION.tsv"), ESC_COLS)
            rules[1]["sla_hours"] = "0"
            write_tsv(p(d, "ESCALATION.tsv"), ESC_COLS, rules)
            return quiet(cmd_check, d)[0] == 1
        guarded("PLANTED sla_hours 0: caught", bad_sla)

        def bp_cite():
            d = fresh("bp")
            if quiet(cmd_check, d)[0] != 0:
                return False
            with open(p(d, "docs", "BLUEPRINT.md"), "a") as f:
                f.write('\n9.7 Enforced by: "a selftest case that does not exist anywhere".\n')
            return red(d)
        guarded("PLANTED blueprint citing a test that does not exist: caught", bp_cite)

        def render_det():
            rows, _ = load_tsv(p(KIT, "TRACE-MATRIX.tsv"), COLS)
            a, b = render(rows), render(list(reversed(rows)))
            return a == b and all(("## " + fw) in a for fw in FRAMEWORKS) and read_text(p(KIT, "TRACE-MATRIX.md")) == a
        guarded("render: deterministic, all frameworks present, checked-in TRACE-MATRIX.md equals a fresh render", render_det)

        def esc_good():
            rules, _ = load_tsv(p(KIT, "ESCALATION.tsv"), ESC_COLS)
            rows, _ = load_tsv(p(KIT, "TRACE-MATRIX.tsv"), COLS)
            with open(p(KIT, "examples", "findings.json")) as f:
                fs = json.load(f)
            issues, _, un = build_issues(fs, rules, rows)
            if un or not issues or len(fs) != 7:
                return False
            for rid, doc in issues.items():
                fl = doc["fields"]
                if sorted(fl) != ["description", "issuetype", "labels", "priority", "project", "summary"]:
                    return False
                if not re.search(r"(?m)^- (EU AI Act|SOC 2 TSC 2017|ISO/IEC 42001|NIST AI RMF) ", fl["description"]):
                    return False
                if read_text(p(KIT, "examples", "escalate-out", rid + ".json")) != json.dumps(doc, indent=1, sort_keys=True) + "\n":
                    return False
            return sorted(os.listdir(p(KIT, "examples", "escalate-out"))) == sorted(r + ".json" for r in issues)
        guarded("escalate: 7 findings give Jira-shaped issues with control ids, equal to checked-in examples/escalate-out", esc_good)

        def esc_unrouted():
            fp = p(tmp, "f.json")
            with open(fp, "w") as f:
                json.dump([{"kind": "meteor_strike", "claim_id": "X-1"}], f)
            rc, out = quiet(cmd_escalate, KIT, fp, None, p(tmp, "o1"), "GRC")
            return rc == 1 and any(x.startswith("UNROUTED") for x in out) and out[-1] == "escalate: 0 issues from 1 findings"
        guarded("PLANTED finding no rule matches: reported UNROUTED, exit 1", esc_unrouted)

        def esc_bad_input():
            fp = p(tmp, "g.json")
            with open(fp, "w") as f:
                f.write("{not json")
            return quiet(cmd_escalate, KIT, fp, None, p(tmp, "o2"), "GRC")[0] == 2 and not os.path.exists(p(tmp, "o2"))
        guarded("PLANTED unreadable findings file: exit 2, nothing written", esc_bad_input)

        def esc_parse():
            log = ("chain: 6/7 links verify\n"
                   "INVALIDATED CD-01 model-card/model-details: CHAIN_BROKEN EV-MODEL; DIGEST_MISMATCH EV-MODEL\n"
                   "claimdiode: 1 of 12 claims INVALIDATED\n")
            fs = parse_verify(log)
            with open(p(KIT, "examples", "findings.json")) as f:
                return fs == [json.load(f)[0]]
        guarded("escalate: a claimdiode verify INVALIDATED line parses to the checked-in finding", esc_parse)

        def ascii_ok():
            names = ["TRACE-MATRIX.md", "TRACE-MATRIX.tsv", "ESCALATION.tsv", "trace.py", os.path.join("docs", "BLUEPRINT.md"),
                     os.path.join("templates", "ml-pipeline-audit.md"), os.path.join("tests", "test_trace.py")]
            for n in names:
                t = read_text(p(KIT, n))
                if t is None or not t.strip() or any(ord(c) > 127 for c in t):
                    return False
            return True
        guarded("new files exist, are non-empty and plain ASCII", ascii_ok)

    n, ok = len(res), sum(res)
    print("trace selftest %d/%d" % (ok, n))
    return 0 if ok == n else 1


def main(argv):
    ap = argparse.ArgumentParser(prog="trace.py")
    ap.add_argument("cmd", nargs="?", choices=["check", "render", "escalate"])
    ap.add_argument("--root", default=KIT)
    ap.add_argument("--findings")
    ap.add_argument("--verify-log")
    ap.add_argument("--out")
    ap.add_argument("--project", default="GRC")
    ap.add_argument("--selftest", action="store_true")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    if a.selftest:
        return selftest()
    if a.cmd == "check":
        return cmd_check(a.root)
    if a.cmd == "render":
        return cmd_render(a.root)
    if a.cmd == "escalate" and a.out and (a.findings or a.verify_log):
        return cmd_escalate(a.root, a.findings, a.verify_log, a.out, a.project)
    print("usage: trace.py check | render | escalate (--findings F.json | --verify-log FILE) --out DIR | --selftest", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
