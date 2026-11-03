#!/usr/bin/env python3
"""grc-autofill: fill GRC report templates from evidence files. stdlib only, no network.

Placeholders: {{NAME}} = AUTO (resolved from evidence), {{J.NAME}} = JUDGMENT (never filled).
A field whose evidence is missing, empty or malformed stays {{NAME}} and is counted. Never blank-filled.
Usage: grc_autofill.py --evidence DIR (<report> | --all) [--out DIR] [--date YYYY-MM-DD] | --selftest
"""
import argparse, contextlib, csv, datetime, glob, io, os, re, sys, tempfile

KIT = os.path.dirname(os.path.abspath(__file__))
PH = re.compile(r"\{\{\s*([A-Za-z0-9_.]+)\s*\}\}")

# ---- IMPL-BEGIN
# evidence key -> file name inside the --evidence directory
FILES = {
    "controls": "CONTROLS.tsv", "risks": "RISK-REGISTER.tsv", "policies": "POLICIES.md",
    "evindex": "EVIDENCE-INDEX.md", "guards": "GUARDS.tsv", "audit": "AUDIT.md",
    "exceptions": "EXCEPTIONS.tsv", "coverage": "COVERAGE.md",
}
# columns each TSV must carry; a missing column or a ragged row marks the file malformed
SCHEMA = {
    "controls": ["id", "control_name", "enforcer_path", "oracle_cmd", "evidence_path", "review_cadence",
                 "nist_csf", "soc2_tsc", "iso27001_annexA"],
    "risks": ["risk_id", "what_could_go_wrong", "how_bad", "likelihood", "inherent_score", "what_stops_it",
              "residual_score", "treatment", "open_gap"],
    "guards": ["control_id", "statement", "tags", "has_selftest", "last_lint_rc", "last_lint_time"],
    "exceptions": ["id", "source", "class", "cause", "age_days", "owner"],
    "hipaa": ["id", "title", "source_url", "quoted_fragment", "fetched", "maps_to", "edge"],
    "sr117": ["id", "title", "source_url", "quoted_fragment", "fetched", "maps_to", "edge"],
    "crosswalk": ["control_id", "csf2", "iso42001_clause", "eu_ai_act_article", "owasp_llm", "ai_rmf_function",
                  "ai_rmf_subcategory", "control_name", "basis"],
}


def evidence_paths(evdir):
    p = {k: os.path.join(evdir, v) for k, v in FILES.items()}
    p["crosswalk"] = os.path.join(KIT, "CROSSWALK.tsv")
    p["hipaa"] = os.path.join(KIT, "sectors", "hipaa-security.tsv")
    p["sr117"] = os.path.join(KIT, "sectors", "sr-11-7.tsv")
    return p


# sector packs: filled on request by name, left out of --all and out of the STANDARDS.tsv artifact set
SECTOR_TEMPLATES = ("hipaa-security-crosswalk", "sr11-7-model-risk")


def templates(tdir):
    return sorted(os.path.basename(p)[:-3] for p in glob.glob(os.path.join(tdir, "*.md")))


def _read_tsv(path, need):
    """Return (rows, malformed). Unreadable or absent file -> (None, False)."""
    try:
        with open(path, newline="") as f:
            reader = csv.DictReader(f, delimiter="\t")
            rows = list(reader)
            cols = reader.fieldnames or []
    except (OSError, UnicodeDecodeError, csv.Error):
        return None, False
    if any(c not in cols for c in need) or any(None in r or None in r.values() for r in rows):
        return None, True
    return rows, False


def _read_txt(path):
    try:
        with open(path) as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


def _cell(s, cap=0):
    s = ("" if s is None else str(s)).replace("|", "/").replace("\n", " ").strip()
    return s[:cap] if cap else s


def _md(headers, rows, cap=0):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(_cell(c, cap) for c in r) + " |" for r in rows]
    return "\n".join(out)


def _group(pairs):
    g = {}
    for k, i in pairs:
        if k:
            g.setdefault(k, [])
            if i not in g[k]:
                g[k].append(i)
    return sorted(g.items())


def _split(s):
    return [x.strip() for x in re.split(r"[;,]", s or "") if x.strip() and x.strip() != "NONE"]


class _Ctx:
    def __init__(self, paths, date, check_fs):
        self.paths, self.date, self.check_fs = paths, date, check_fs
        self.cache, self.flagged, self.malformed = {}, set(), set()

    def tsv(self, key):
        if key not in self.cache:
            rows, bad = _read_tsv(self.paths.get(key, ""), SCHEMA.get(key, []))
            if bad:
                self.malformed.add(key)
            self.cache[key] = rows if rows else None
        return self.cache[key]

    def txt(self, key):
        k = "t:" + key
        if k not in self.cache:
            t = _read_txt(self.paths.get(key, ""))
            self.cache[k] = t if t and t.strip() else None
        return self.cache[k]

    def resolve(self, name):
        try:
            return RES[name](self)
        except (KeyError, ValueError, IndexError):
            return None


def _ev_check(c, r):
    ev = (r.get("evidence_path") or "").strip()
    if not ev:
        c.flagged.add(r["id"])
        return "NO-EVIDENCE"
    first = re.split(r"[ ;]", ev)[0]
    base = os.path.dirname(c.paths.get("controls", ""))
    if c.check_fs and not os.path.exists(os.path.join(base, first)):
        c.flagged.add(r["id"])
        return "EVIDENCE-FILE-MISSING"
    return "ok"


def _r_control_table(c):
    rows = c.tsv("controls")
    if not rows:
        return None
    return _md(["Control", "Name", "Enforcer", "Oracle command", "Evidence path", "Cadence", "Check"],
               [[r["id"], r["control_name"], r["enforcer_path"], r["oracle_cmd"], r["evidence_path"],
                 r["review_cadence"], _ev_check(c, r)] for r in rows])


def _r_oracles(c):
    rows = c.tsv("controls")
    return "\n".join("- %s: `%s`" % (r["id"], r["oracle_cmd"]) for r in rows) if rows else None


def _open_risks(c):
    rows = c.tsv("risks")
    return [r for r in rows if r["open_gap"].strip().lower().startswith("yes")] if rows else None


def _r_poam(c):
    rr = _open_risks(c)
    if not rr:
        return None
    return _md(["Item", "Weakness", "Risk", "Controls", "Residual", "Status", "Owner / due / milestones"],
               [["P-" + r["risk_id"], re.sub(r"^yes:\s*", "", r["open_gap"], flags=re.I), r["what_could_go_wrong"],
                 r["what_stops_it"], r["residual_score"], "open", "owner to set"] for r in rr])


def _r_exc_counts(c):
    rows = c.tsv("exceptions")
    if not rows:
        return None
    n = {}
    for r in rows:
        n[r["class"]] = n.get(r["class"], 0) + 1
    return "; ".join("%s: %d" % kv for kv in sorted(n.items()))


def _r_exc_table(c):
    rows = c.tsv("exceptions")
    if not rows:
        return None

    def age(r):
        return int(r["age_days"]) if r["age_days"].isdigit() else -1
    top = sorted(rows, key=age, reverse=True)[:30]
    return _md(["Id", "Class", "Cause", "Age (days)", "Owner"],
               [[r["id"], r["class"], r["cause"], r["age_days"], r["owner"]] for r in top], 120) + \
        "\n\nShowing %d of %d exception rows (oldest first)." % (len(top), len(rows))


def _r_guard_stats(c):
    g = c.tsv("guards")
    if not g:
        return None
    z = sum(1 for r in g if r["last_lint_rc"].strip() == "0")
    u = sum(1 for r in g if r["last_lint_rc"].strip() in ("UNKNOWN", ""))
    return "guards %d; with selftest %d; last lint rc 0: %d; rc non-zero: %d; UNKNOWN: %d" % (
        len(g), sum(1 for r in g if r["has_selftest"].strip() == "Y"), z, len(g) - z - u, u)


def _r_guard_red(c):
    g = c.tsv("guards")
    if not g:
        return None
    bad = [r for r in g if r["last_lint_rc"].strip() not in ("0", "UNKNOWN", "")]
    return _md(["Guard", "Statement", "Last lint rc", "Time"],
               [[r["control_id"], r["statement"], r["last_lint_rc"], r["last_lint_time"]] for r in bad], 110) if bad else None


def _r_audit(c):
    t = c.txt("audit")
    if not t:
        return None
    return "\n".join("> " + ln for ln in [x for x in t.splitlines() if x.strip()][:15])


def _matrix(c, col, head1, head2):
    rows = c.tsv("controls")
    if not rows:
        return None
    pairs = [(x, r["id"]) for r in rows for x in _split(r[col])]
    return _md([head1, head2, "Count"], [[k, ", ".join(v), len(v)] for k, v in _group(pairs)])


def _r_csf_fn(c):
    rows = c.tsv("controls")
    if not rows:
        return None
    n = {}
    for r in rows:
        for x in _split(r["nist_csf"]):
            f = x.split(".")[0]
            n[f] = n.get(f, 0) + 1
    return "; ".join("%s: %d" % kv for kv in sorted(n.items()))


def _guard_tag_table(c, prefix, head, first=True):
    g = c.tsv("guards")
    if not g:
        return None
    pairs = [(t.split(":", 1)[1], r["control_id"]) for r in g for t in _split(r["tags"]) if t.startswith(prefix)]
    if first:
        return _md([head, "Guard count", "First guards"], [[k, len(v), ", ".join(v[:6])] for k, v in _group(pairs)])
    return _md([head, "Guard count"], [[k, len(v)] for k, v in _group(pairs)])


def _r_xw_cov(c):
    x = c.tsv("crosswalk")
    if not x:
        return None
    cols = ["ai_rmf_function", "ai_rmf_subcategory", "csf2", "iso42001_clause", "eu_ai_act_article", "owasp_llm"]
    return "rows %d; " % len(x) + "; ".join("%s non-blank %d" % (k, sum(1 for r in x if r.get(k, "").strip())) for k in cols)


def _r_owasp(c):
    t = c.txt("coverage")
    if not t:
        return None
    rows = [[x.strip() for x in ln.strip().strip("|").split("|")] for ln in t.splitlines() if re.match(r"\|\s*LLM\d\d", ln)]
    rows = [r[:4] for r in rows if len(r) >= 4]
    return _md(["Id", "Title", "Runnable evidence", "Status"], rows, 160) if rows else None


def _r_policies(c):
    t = c.txt("policies")
    h = [ln[3:].strip() for ln in t.splitlines() if re.match(r"## P\d", ln)] if t else None
    return "\n".join("- " + x for x in h) if h else None


def _r_scope(c):
    t = c.txt("policies")
    s = [ln for ln in t.splitlines() if ln.startswith("Scope:")] if t else None
    return s[0] if s else None


def _r_evcmd(c):
    t = c.txt("evindex")
    rows = [ln for ln in t.splitlines() if re.match(r"\|\s*C-\d", ln)] if t else None
    return "| Control | Command | Receipt |\n|---|---|---|\n" + "\n".join(rows) if rows else None


def _cnt(key):
    return lambda c: str(len(c.tsv(key))) if c.tsv(key) else None


def _r_risk_table(c):
    rows = c.tsv("risks")
    if not rows:
        return None
    return _md(["Risk", "What could go wrong", "Impact", "Likelihood", "Inherent", "Controls", "Residual", "Treatment", "Open gap"],
               [[r["risk_id"], r["what_could_go_wrong"], r["how_bad"], r["likelihood"], r["inherent_score"],
                 r["what_stops_it"], r["residual_score"], r["treatment"], r["open_gap"]] for r in rows], 140)


def _r_open_cnt(c):
    rr = c.tsv("risks")
    return str(len(_open_risks(c))) if rr else None


def _sector_rows(c, key):
    """Sector rows, or None when the file is absent, empty, or a maps_to id is not in CROSSWALK.tsv."""
    rows, x = c.tsv(key), c.tsv("crosswalk")
    if not rows or not x:
        return None
    ids = set(r["control_id"] for r in x)
    if any(i not in ids for r in rows for i in _split(r["maps_to"])):
        return None
    return rows


def _r_sector_table(key):
    def f(c):
        rows = _sector_rows(c, key)
        if not rows:
            return None
        return _md(["Id", "Requirement", "Source", "Fetched", "Quoted fragment", "Mapped controls", "Edge"],
                   [[r["id"], r["title"], r["source_url"], r["fetched"], r["quoted_fragment"] or "not fetched",
                     r["maps_to"] or "none", r["edge"]] for r in rows])
    return f


def _r_sector_status(key):
    def f(c):
        rows = _sector_rows(c, key)
        if not rows:
            return None
        n = sum(1 for r in rows if r["fetched"] == "yes")
        g = sum(1 for r in rows if r["edge"] == "GROUNDED")
        return "rows %d; fetched %d/%d; GROUNDED edges %d; INFERRED edges %d" % (len(rows), n, len(rows), g, len(rows) - g)
    return f


# AUTO placeholder name -> resolver. A new AUTO field is one entry here; a new report is just a template file.
RES = {
    "REPORT_DATE": lambda c: c.date,
    "SCOPE_STATEMENT": _r_scope,
    "POLICY_LIST": _r_policies,
    "CONTROL_COUNT": _cnt("controls"),
    "RISK_COUNT": _cnt("risks"),
    "GUARD_COUNT": _cnt("guards"),
    "OPEN_RISK_COUNT": _r_open_cnt,
    "CONTROL_TABLE": _r_control_table,
    "CONTROL_ORACLE_LIST": _r_oracles,
    "EVIDENCE_COMMAND_TABLE": _r_evcmd,
    "RISK_TABLE": _r_risk_table,
    "POAM_TABLE": _r_poam,
    "EXCEPTION_COUNTS": _r_exc_counts,
    "EXCEPTION_TABLE": _r_exc_table,
    "GUARD_STATS": _r_guard_stats,
    "GUARD_RED_TABLE": _r_guard_red,
    "AUDIT_EXCERPT": _r_audit,
    "SOC2_CONTROL_MATRIX": lambda c: _matrix(c, "soc2_tsc", "Criterion", "Controls"),
    "SOC2_GUARD_COUNTS": lambda c: _guard_tag_table(c, "SOC2:", "Criterion", first=False),
    "ISO27001_ANNEX_TABLE": lambda c: _matrix(c, "iso27001_annexA", "Annex A id", "Controls present"),
    "CSF_CURRENT_TABLE": lambda c: _matrix(c, "nist_csf", "CSF 2.0 id", "Controls (current)"),
    "CSF_FUNCTION_COUNTS": _r_csf_fn,
    "AIRMF_FUNCTION_TABLE": lambda c: _guard_tag_table(c, "NIST:", "AI RMF function"),
    "ISO42001_CLAUSE_TABLE": lambda c: _guard_tag_table(c, "ISO42001:", "ISO 42001 clause"),
    "CROSSWALK_COVERAGE": _r_xw_cov,
    "OWASP_TABLE": _r_owasp,
    "HIPAA_REQUIREMENT_TABLE": _r_sector_table("hipaa"),
    "HIPAA_ROW_STATUS": _r_sector_status("hipaa"),
    "SR117_REQUIREMENT_TABLE": _r_sector_table("sr117"),
    "SR117_ROW_STATUS": _r_sector_status("sr117"),
}


def fill_text(text, paths, date, check_fs=True):
    ctx = _Ctx(paths, date, check_fs)
    st = {"auto_total": 0, "auto_filled": 0, "judgment": 0, "unknown": 0, "missing": 0, "flagged": 0, "malformed": []}

    def sub(m):
        name = m.group(1)
        if name.startswith("J."):
            st["judgment"] += 1
            return m.group(0)
        if name not in RES:
            st["unknown"] += 1
            return m.group(0)
        st["auto_total"] += 1
        val = ctx.resolve(name)
        if val is None or not str(val).strip():
            st["missing"] += 1
            return m.group(0)
        st["auto_filled"] += 1
        return str(val)
    out = PH.sub(sub, text)
    st["flagged"] = len(ctx.flagged)
    st["malformed"] = sorted(ctx.malformed)
    return out, st


def fill_report(report, paths, date, templates_dir, out_dir, check_fs=True):
    with open(os.path.join(templates_dir, report + ".md")) as f:
        text = f.read()
    out, st = fill_text(text, paths, date, check_fs)
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "%s-%s.md" % (report, date))
    with open(path, "w", newline="") as f:
        f.write(out)
    return path, st


def summary_line(label, st):
    return "grc-autofill: %sAUTO %d/%d fields filled, JUDGMENT %d left" % (
        label + " " if label else "", st["auto_filled"], st["auto_total"], st["judgment"])
# ---- IMPL-END


def _w(path, text):
    with open(path, "w", newline="") as f:
        f.write(text)


def _fixture(d, with_risks=True):
    ev1 = os.path.join(d, "ev1.txt")
    _w(ev1, "receipt\n")
    hdr = "id\tcontrol_name\twhat_it_stops\tenforcer_path\toracle_cmd\tevidence_path\tnist_csf\tnist_80053\tsoc2_tsc\tiso27001_annexA\towner\treview_cadence\n"
    rows = [
        "C-01\tAccess filter\tstops x\tsrc/a.py\tmake a\tev1.txt\tPR.PS-01\tAC-6\tCC6.1\tA.8.2\tops\tweekly\n",
        "C-02\tNo evidence ctl\tstops x\tsrc/b.py\tmake b\t\tPR.PS-02\tCM-5\tCC8.1\tA.8.9\tops\tweekly\n",
        "C-03\tGhost evidence ctl\tstops y\tsrc/c.py\tmake c\tnope.txt\tDE.CM-09\tSI-4\tCC7.2\tA.8.16\tops\tmonthly\n",
    ]
    _w(os.path.join(d, "CONTROLS.tsv"), hdr + "".join(rows))
    rh = "risk_id\twhat_could_go_wrong\thow_bad\tlikelihood\tinherent_score\twhat_stops_it\tresidual_score\ttreatment\topen_gap\n"
    rr = ["R-01\tleak\t5\t3\t15\tC-01;C-02\t10\tmitigate\tno\n",
          "R-10\tinjection\t4\t4\t16\tC-03\t8\tmitigate\tyes: no detector yet\n"]
    if with_risks:
        _w(os.path.join(d, "RISK-REGISTER.tsv"), rh + "".join(rr))
    gh = "control_id\tstatement\ttags\thas_selftest\tlast_lint_rc\tlast_lint_time\tguard_sha8\n"
    _w(os.path.join(d, "GUARDS.tsv"), gh +
       "g-a\tdrift a\tNIST:GOVERN,ISO42001:8,SOC2:CC7\tY\t0\t2026-11-02T00:00:00Z\taaaaaaaa\n"
       "g-b\tdrift b\tNONE\tN\t1\t2026-11-02T00:00:00Z\tbbbbbbbb\n")
    _w(os.path.join(d, "POLICIES.md"), "# Policies\n\nScope: one service, one team.\n\n## P1. Change management\n\n## P2. Access\n")
    _w(os.path.join(d, "EVIDENCE-INDEX.md"), "# Evidence index\n\n| Control | Command | Receipt |\n|---|---|---|\n| C-01 | `x` | `y` |\n")
    _w(os.path.join(d, "AUDIT.md"), "# Audit\nline one\nline two\n")
    _w(os.path.join(d, "EXCEPTIONS.tsv"), "id\tsource\tclass\tcause\tage_days\towner\nex-1\tG.tsv\tOPEN\tno owner\t6\tops\n")
    _w(os.path.join(d, "COVERAGE.md"), "## OWASP\n\n| Id | Title | Evidence | Status |\n|---|---|---|---|\n| LLM01 | Prompt Injection | make a | COVERED |\n")
    return evidence_paths(d)


def _quiet(fn, *a):
    """Run fn with stdout and stderr captured; return fn's result."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(*a)


def selftest():
    res = []

    def chk(name, ok):
        res.append(bool(ok))
        print(("PASS " if ok else "FAIL ") + name)

    def guarded(name, fn):
        try:
            chk(name, fn())
        except Exception as e:  # a crash is a failed check, never a skip
            chk(name + " (raised %s)" % type(e).__name__, False)

    D = "2026-11-02"
    tdir = os.path.join(KIT, "templates")
    with tempfile.TemporaryDirectory() as d:
        P = _fixture(d)
        tpl = "n={{CONTROL_COUNT}} r={{RISK_COUNT}} {{J.NOTE}}"

        def t1():
            out, st = fill_text(tpl, P, D)
            return out == "n=3 r=2 {{J.NOTE}}" and st["auto_filled"] == 2 and st["auto_total"] == 2 and st["judgment"] == 1
        guarded("all AUTO filled when evidence present", t1)

        def t2():
            out, st = fill_text("{{CONTROL_COUNT}} {{CONTROL_COUNT}}", P, D)
            return st["auto_filled"] == 2 and st["auto_total"] == 2
        guarded("repeated placeholder counted per occurrence", t2)

        def t3():
            with tempfile.TemporaryDirectory() as d2:
                P2 = _fixture(d2, with_risks=False)
                out, st = fill_text(tpl, P2, D)
                return "{{RISK_COUNT}}" in out and st["auto_filled"] == 1 and st["auto_total"] == 2 and st["missing"] == 1
        guarded("PLANTED missing evidence file: placeholder kept and counted", t3)

        def t4():
            out, st = fill_text("a {{NOPE}} b {{J.X}} {{CONTROL_COUNT}}", P, D)
            return "{{NOPE}}" in out and st["unknown"] == 1 and st["auto_total"] == 1 and st["judgment"] == 1
        guarded("PLANTED unknown placeholder: counted and left", t4)

        def t5():
            out, st = fill_text("{{J.CONTROL_COUNT}} {{J.RISK_TABLE}}", P, D)
            return out == "{{J.CONTROL_COUNT}} {{J.RISK_TABLE}}" and st["judgment"] == 2 and st["auto_total"] == 0
        guarded("PLANTED judgment field with matching evidence: never filled", t5)

        def t6():
            out, st = fill_text("{{CONTROL_TABLE}}", P, D)
            return "NO-EVIDENCE" in out and "EVIDENCE-FILE-MISSING" in out and st["flagged"] == 2
        guarded("control with no or missing evidence file is flagged", t6)

        def t7():
            out, st = fill_text("{{CONTROL_TABLE}}", P, D)
            row = [ln for ln in out.splitlines() if ln.startswith("| C-01")]
            return len(row) == 1 and row[0].rstrip().endswith("| ok |")
        guarded("control with evidence on disk is not flagged", t7)

        def t8():
            with tempfile.TemporaryDirectory() as d2:
                P2 = _fixture(d2)
                _w(P2["risks"], "risk_id\twhat_could_go_wrong\thow_bad\tlikelihood\tinherent_score\twhat_stops_it\tresidual_score\ttreatment\topen_gap\n")
                out, st = fill_text("{{RISK_TABLE}}", P2, D)
                return out == "{{RISK_TABLE}}" and st["missing"] == 1 and st["auto_filled"] == 0
        guarded("PLANTED header-only evidence: never blank-filled", t8)

        def t9():
            out, st = fill_text("{{POAM_TABLE}}", P, D)
            return "R-10" in out and "R-01" not in out
        guarded("POA&M table lists only risks with an open gap", t9)

        def t10():
            with tempfile.TemporaryDirectory() as d2:
                P2 = _fixture(d2)
                _w(P2["controls"], open(P["controls"]).read() + "C-04\tshort row\n")
                out, st = fill_text("{{CONTROL_COUNT}}", P2, D)
                return out == "{{CONTROL_COUNT}}" and st["malformed"] == ["controls"] and st["missing"] == 1
        guarded("PLANTED malformed TSV (short row): caught, field left unfilled", t10)

        def t11():
            with tempfile.TemporaryDirectory() as d2:
                P2 = _fixture(d2)
                _w(P2["risks"], "risk_id\tdescription\nR-1\tx\n")
                out, st = fill_text("{{RISK_COUNT}}", P2, D)
                return out == "{{RISK_COUNT}}" and st["malformed"] == ["risks"]
        guarded("PLANTED malformed TSV (required column absent): caught", t11)

        def t12():
            with tempfile.TemporaryDirectory() as d2, tempfile.TemporaryDirectory() as od:
                _fixture(d2)
                _w(os.path.join(d2, "RISK-REGISTER.tsv"), "risk_id\tx\n1\n")
                return _quiet(main, ["--evidence", d2, "ssp", "--out", od, "--date", D]) == 1
        guarded("CLI: malformed evidence exits 1", t12)

        def t13():
            with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as od:
                _w(os.path.join(td, "x.md"), "## S\nAUTO: controls\nn={{CONTROL_COUNT}} {{J.A}} {{J.B}}\n")
                path, st = fill_report("x", P, D, td, od)
                line = summary_line("x", st)
                return (os.path.basename(path) == "x-%s.md" % D and os.path.exists(path)
                        and line == "grc-autofill: x AUTO 1/1 fields filled, JUDGMENT 2 left")
        guarded("writes <report>-<date>.md and prints the exact summary line", t13)

        def t14():
            with tempfile.TemporaryDirectory() as od:
                return _quiet(main, ["--evidence", d, "no-such-report", "--out", od]) == 2
        guarded("CLI: unknown report exits 2", t14)

        def t15():
            return _quiet(main, []) == 2
        guarded("CLI: no args exits 2", t15)

        def t16():
            with tempfile.TemporaryDirectory() as td:
                for p in glob.glob(tdir + "/*.md"):
                    _w(os.path.join(td, os.path.basename(p)), open(p).read())
                before = templates(td)
                _w(os.path.join(td, "brand-new-report.md"), "## S\nAUTO: x\n{{RISK_COUNT}} {{J.Z}}\n")
                after = templates(td)
                return len(before) >= 1 and after == sorted(before + ["brand-new-report"])
        guarded("fan-out by data: a dropped template is a new report, no code edit", t16)

    found = [r for r in templates(tdir) if r not in SECTOR_TEMPLATES]

    def t17():
        return len(found) >= 1
    guarded("templates found (non-empty set)", t17)

    def t18():
        with open(os.path.join(KIT, "STANDARDS.tsv"), newline="") as f:
            rows = list(csv.DictReader(f, delimiter="\t"))
        arts = sorted(set(a for r in rows for a in r["artifact"].split(";")))
        return len(rows) > 0 and arts == found
    guarded("every artifact named in STANDARDS.tsv has a template and vice versa", t18)

    def t19():
        bad = []
        for r in found or [None]:
            _, st = fill_text(open(os.path.join(tdir, r + ".md")).read(), {}, D)
            if st["unknown"]:
                bad.append(r)
        return bool(found) and not bad
    guarded("no unknown placeholder in any shipped template", t19)

    def t20():
        for r in found or [None]:
            secs = re.split(r"(?m)^## ", open(os.path.join(tdir, r + ".md")).read())[1:]
            if not secs or any(not re.search(r"(?m)^(AUTO|JUDGMENT):", s) for s in secs):
                return False
        return True
    guarded("every template section declares AUTO or JUDGMENT", t20)

    def t21():
        for r in found or [None]:
            txt = open(os.path.join(tdir, r + ".md")).read()
            if not re.search(r"\{\{J\.", txt) or not any(not m.group(1).startswith("J.") for m in PH.finditer(txt)):
                return False
        return True
    guarded("every template has both AUTO and JUDGMENT fields", t21)

    def t22():
        for name in [os.path.join("templates", r + ".md") for r in found] + ["STANDARDS.tsv", "CROSSWALK.tsv"]:
            if any(ord(c) > 127 for c in open(os.path.join(KIT, name)).read()):
                return False
        return True
    guarded("templates and TSVs are ASCII only", t22)

    def t23():
        with open(os.path.join(KIT, "CROSSWALK.tsv"), newline="") as f:
            rows = list(csv.DictReader(f, delimiter="\t"))
        mapped = [r for r in rows if r["owasp_llm"].strip()]
        return len(mapped) > 0 and all("INFERRED" in r["basis"] for r in mapped) and all(r["basis"].strip() for r in rows)
    guarded("crosswalk keeps provenance: every OWASP mapping is marked INFERRED", t23)

    def t24():
        ev = os.path.join(KIT, "examples", "evidence")
        outd = os.path.join(KIT, "examples", "out")
        with tempfile.TemporaryDirectory() as od:
            for r in found:
                fill_report(r, evidence_paths(ev), D, tdir, od)
            names = sorted(os.listdir(od))
            if not names or names != sorted(os.listdir(outd)):
                return False
            return all(open(os.path.join(od, n)).read() == open(os.path.join(outd, n)).read() for n in names)
    guarded("examples/out is exactly what the demo evidence generates", t24)

    def t25():
        ev = os.path.join(KIT, "examples", "evidence")
        tj = 0
        with tempfile.TemporaryDirectory() as od:
            for r in found:
                path, st = fill_report(r, evidence_paths(ev), D, tdir, od)
                txt = open(path).read()
                left = len(re.findall(r"\{\{J\.", txt))
                tj += left
                if left != st["judgment"] or left != len(re.findall(r"\{\{J\.", open(os.path.join(tdir, r + ".md")).read())):
                    return False
        return tj > 0
    guarded("demo run: every JUDGMENT placeholder survives into the output", t25)

    def t26():
        ev = os.path.join(KIT, "examples", "evidence")
        with tempfile.TemporaryDirectory() as od:
            for r in SECTOR_TEMPLATES:
                path, st = fill_report(r, evidence_paths(ev), D, tdir, od)
                if st["unknown"] or st["missing"] or not st["auto_total"] or "{{J." not in open(path).read():
                    return False
        return templates(tdir) == sorted(found + list(SECTOR_TEMPLATES))
    guarded("sector templates fill with zero unresolved AUTO and keep JUDGMENT fields", t26)

    def t27():
        for key, tn in (("hipaa", "HIPAA_REQUIREMENT_TABLE"), ("sr117", "SR117_REQUIREMENT_TABLE")):
            with tempfile.TemporaryDirectory() as d2:
                P2 = evidence_paths(d2)
                src = open(evidence_paths(d2)[key]).read().splitlines()
                bad = src[:2]
                cols = bad[1].split("\t")
                cols[5] = "C-99"
                _w(os.path.join(d2, "s.tsv"), src[0] + "\n" + "\t".join(cols) + "\n")
                P2[key] = os.path.join(d2, "s.tsv")
                out, st = fill_text("{{%s}}" % tn, P2, D)
                if out != "{{%s}}" % tn or st["missing"] != 1:
                    return False
                P2[key] = evidence_paths(d2)[key]
                out, st = fill_text("{{%s}}" % tn, P2, D)
                if st["missing"] != 0 or "C-99" in out:
                    return False
        return True
    guarded("PLANTED unknown control id in a sector pack: field left unfilled, real pack fills", t27)

    def t28():
        for key in ("hipaa", "sr117"):
            with open(evidence_paths(KIT)[key], newline="") as f:
                rows = list(csv.DictReader(f, delimiter="\t"))
            if not rows or any(not r["source_url"].startswith("https://") for r in rows):
                return False
            if any(r["fetched"] == "yes" and not r["quoted_fragment"].strip() for r in rows):
                return False
            if any(r["fetched"] == "no" and (r["quoted_fragment"].strip() or r["edge"] != "INFERRED") for r in rows):
                return False
        return all(ord(c) < 128 for k in ("hipaa", "sr117") for c in open(evidence_paths(KIT)[k]).read())
    guarded("sector rows keep provenance: url on all, quote on fetched, none invented on unfetched", t28)

    n, ok = len(res), sum(res)
    print("grc-autofill selftest %d/%d" % (ok, n))
    return 0 if ok == n else 1


def main(argv):
    ap = argparse.ArgumentParser(prog="grc_autofill.py")
    ap.add_argument("report", nargs="?")
    ap.add_argument("--evidence")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--out", default="out")
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    ap.add_argument("--selftest", action="store_true")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    if a.selftest:
        return selftest()
    tdir = os.path.join(KIT, "templates")
    avail = templates(tdir)
    todo = [r for r in avail if r not in SECTOR_TEMPLATES] if a.all else ([a.report] if a.report else [])
    if not a.evidence or not todo or (a.report and a.report not in avail) or (a.all and a.report):
        print("usage: grc_autofill.py --evidence DIR (<%s> | --all) [--out DIR] [--date D] | --selftest" % "|".join(avail), file=sys.stderr)
        return 2
    ta = tf = tj = 0
    bad = set()
    paths = evidence_paths(a.evidence)
    for r in todo:
        path, st = fill_report(r, paths, a.date, tdir, a.out)
        print("grc-autofill: %s unknown=%d missing=%d flagged=%d -> %s" % (r, st["unknown"], st["missing"], st["flagged"], path))
        print(summary_line(r, st))
        ta += st["auto_total"]
        tf += st["auto_filled"]
        tj += st["judgment"]
        bad.update(st["malformed"])
    for k in sorted(bad):
        print("grc-autofill: MALFORMED evidence %s (treated as missing)" % FILES.get(k, k))
    print(summary_line("", {"auto_filled": tf, "auto_total": ta, "judgment": tj}))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
