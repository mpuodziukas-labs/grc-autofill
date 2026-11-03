"""Deny-by-default role to action check with separation of duties and an audit log.

Policy lives in rbac-policy.json. Standard library only.
  rbac.py check <role> <action> [--author X --actor Y] [--audit-log FILE]   exit 0 allow, 1 deny
  rbac.py --selftest
Scope: a policy decision function. It does not authenticate anyone; role, actor and author are
caller-supplied strings.
"""
import argparse
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
POLICY = os.path.join(HERE, "rbac-policy.json")
SOD_ACTIONS = ("approve_report",)


def load_policy(path=POLICY):
    """Return the policy dict, or None when missing or malformed (callers then deny everything)."""
    try:
        with open(path) as f:
            pol = json.load(f)
        roles = pol["roles"]
        ok = isinstance(roles, dict) and roles and all(
            isinstance(v, list) and all(isinstance(a, str) and a and "*" not in a for a in v) for v in roles.values())
        return pol if ok else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def decide(pol, role, action, author=None, actor=None):
    """Return (allowed, reason). Anything not explicitly allowed is denied."""
    if pol is None:
        return False, "policy missing or malformed: deny all"
    roles = pol["roles"]
    if role not in roles:
        return False, "unknown role %r" % role
    if action not in roles[role]:
        return False, "role %r is not granted %r" % (role, action)
    sod = [r.get("action") for r in pol.get("separation_of_duties", []) if isinstance(r, dict)]
    if action in sod or action in SOD_ACTIONS:
        if not author or not actor:
            return False, "separation of duties: author and actor are both required for %r" % action
        if author == actor:
            return False, "separation of duties: %r authored this report and cannot %s it" % (actor, action)
    return True, "role %r is granted %r" % (role, action)


def check(pol, role, action, author=None, actor=None, log=None):
    allowed, reason = decide(pol, role, action, author, actor)
    if log is not None:
        log.append({"seq": len(log) + 1, "role": role, "action": action, "author": author,
                    "actor": actor, "allowed": allowed, "reason": reason})
    return allowed, reason


def selftest():
    good = load_policy()
    cases = []

    def case(name, got, want):
        cases.append((name, got == want))

    def d(*a, **k):
        return decide(good, *a, **k)[0]

    case("policy loads", good is not None, True)
    case("viewer reads", d("viewer", "read_report"), True)
    case("viewer cannot edit judgment", d("viewer", "edit_judgment"), False)
    case("viewer cannot approve", d("viewer", "approve_report", "a", "b"), False)
    case("analyst edits judgment", d("analyst", "edit_judgment"), True)
    case("analyst cannot change rules", d("analyst", "change_rules"), False)
    case("approver approves another's report", d("approver", "approve_report", "alice", "bob"), True)
    case("PLANTED author approves own report", d("approver", "approve_report", "alice", "alice"), False)
    case("PLANTED approve without author or actor", d("approver", "approve_report"), False)
    case("PLANTED approve with actor only", d("approver", "approve_report", None, "bob"), False)
    case("admin changes rules", d("admin", "change_rules"), True)
    case("admin cannot approve (no grant)", d("admin", "approve_report", "a", "b"), False)
    case("PLANTED unknown role", d("intern", "read_report"), False)
    case("PLANTED unknown action", d("admin", "delete_everything"), False)
    case("PLANTED empty role", d("", "read_report"), False)
    case("PLANTED missing policy denies all", decide(None, "admin", "change_rules")[0], False)

    with tempfile.TemporaryDirectory() as t:
        bad = os.path.join(t, "bad.json")
        with open(bad, "w") as f:
            f.write('{"roles": {"viewer": ["*"]}}')
        case("PLANTED wildcard grant rejects policy", load_policy(bad), None)
        with open(bad, "w") as f:
            f.write("not json")
        case("PLANTED malformed policy rejected", load_policy(bad), None)

    log = []
    check(good, "viewer", "change_rules", log=log)
    check(good, "analyst", "edit_judgment", log=log)
    case("audit log has one row per decision", [r["allowed"] for r in log], [False, True])
    case("audit rows carry a reason", all(r["reason"] for r in log), True)

    for name, ok in cases:
        if not ok:
            print("FAIL " + name)
    n = sum(1 for _, ok in cases if ok)
    print("rbac selftest %d/%d" % (n, len(cases)))
    return 0 if n == len(cases) and cases else 1


def main(argv):
    ap = argparse.ArgumentParser(prog="rbac.py")
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    c = sub.add_parser("check")
    c.add_argument("role")
    c.add_argument("action")
    c.add_argument("--author")
    c.add_argument("--actor")
    c.add_argument("--audit-log")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    if a.cmd != "check":
        ap.print_usage()
        return 2
    log = []
    allowed, reason = check(load_policy(), a.role, a.action, a.author, a.actor, log)
    if a.audit_log:
        with open(a.audit_log, "a") as f:
            f.write(json.dumps(log[0], sort_keys=True) + "\n")
    print("%s %s" % ("ALLOW" if allowed else "DENY", reason))
    return 0 if allowed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
