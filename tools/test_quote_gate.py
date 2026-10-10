#!/usr/bin/env python3
"""Unit tests for quote approval gate in cothe_run_test (no Discord, no scan)."""
import json, os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cothe_run_test as core

posts = []
core.post_webhook = lambda **kw: posts.append(kw) or True
core.resolve_photo = lambda info, messages=None: info
core.save_seen = lambda d: None
core.load_seen = lambda: {}

BASE_QUOTE = {
    "tier": "Home Check",
    "lines": ["Home Check: $199.00"],
    "subtotal": 199, "discountAmt": 0, "taxable": 0, "taxRate": 0, "tax": 0,
    "oneTimeTotal": 199, "monitoring": "None", "monthly": 0, "monthlyTax": 0,
    "monthlyTotal": 0, "salesRep": "Alex", "createdAt": "2026-10-10T12:00:00Z",
}


def make_answers(**kw):
    q = kw.pop("quote", dict(BASE_QUOTE))
    h = core.quote_hash(q) if isinstance(q, dict) else ""
    d = {
        "authorizingPerson": {
            "typedLegalName": "Jane Doe",
            "signaturePresent": True,
            "identityPhotoPresent": True,
            "photo_code": None,
        },
        "client": {"organization": "Acme"},
        "engagement": {"clientIp": "8.8.8.8"},
        "quote": q,
        "quote_approved": True,
        "quote_approved_by": "Jane Doe",
        "quote_approved_date": "2026-10-10",
        "quote_signature_captured": True,
        "quote_hash": h,
    }
    d.update(kw)
    return d


def check(answers):
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    json.dump(answers, open(path, "w"))
    info = core.extract_from_answers(path)
    os.unlink(path)
    return info, core.validate_authorization(info), core.validate_quote(info)


def main():
    info, (ok, missing), qr = check(make_answers())
    assert ok and qr == [], (ok, missing, qr)
    print("ok approved+signed")

    _, (ok, _), qr = check(make_answers(quote_approved=False))
    assert not ok and any("not approved" in x for x in qr), qr
    print("ok unapproved")

    a = make_answers()
    a["quote"] = dict(a["quote"])
    a["quote"]["oneTimeTotal"] = 1.0
    _, (ok, _), qr = check(a)
    assert not ok and any("mismatch" in x for x in qr), qr
    print("ok tampered total")

    _, (ok, _), qr = check(make_answers(
        quote="none", quote_approved=False, quote_approved_by="",
        quote_signature_captured=False, quote_hash=""))
    assert not ok and qr == ["no quote attached"], qr
    print("ok no quote")

    core.run_scan = lambda ip: (_ for _ in ()).throw(RuntimeError("scan blocked"))
    fd, path = tempfile.mkstemp(suffix=".json"); os.close(fd)
    json.dump(make_answers(quote_approved=False), open(path, "w"))
    posts.clear()
    old = sys.argv
    sys.argv = ["cothe_run_test.py", "--answers", path, "--operator", "T", "--auth-id", "gate-u"]
    try:
        core.main(); code = 0
    except SystemExit as e:
        code = e.code
    sys.argv = old; os.unlink(path)
    assert code == 2 and posts and "quote not approved/signed" in posts[0]["content"], (code, posts)
    print("ok refusal posts quote gate message (mocked webhook)")

    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
