#!/usr/bin/env python3
"""Unit tests for quote approval gate in cothe_run_test (no Discord, no scan)."""
import json, os, sys, tempfile
_PAY_DIR = tempfile.mkdtemp()
os.environ["COTHE_PAYMENTS_FILE"] = os.path.join(_PAY_DIR, "payments.json")
os.environ.pop("STRIPE_SECRET_KEY", None)
os.environ["COTHE_DISCORD_BOT_TOKEN"] = "test-token-not-real"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cothe_run_test as core
import cothe_payments as payments

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
    "quote_id": "Q20261010-abc123", "clientName": "Jane Doe",
    "clientEmail": "Jane.Doe@Gmail.com", "clientCompany": "Acme",
    "tierId": "smb", "extraDevices": 0, "extraSites": 0,
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
        "client": {"organization": "Acme", "contact": "jane  doe, Owner", "email": " jane.doe@gmail.com "},
        "scope_check": {"answers": {"use": "business", "devices": 8, "sites": 1, "wifi": "yes"}},
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

    def run_main(ans, auth_id, pay=True):
        if pay and not payments.find_payment(auth_id):
            payments.record_cash(auth_id, 199, "Cash Tester", "cashtester", "src-" + auth_id)
        fd, path = tempfile.mkstemp(suffix=".json"); os.close(fd)
        json.dump(ans, open(path, "w")); posts.clear()
        old = sys.argv
        sys.argv = ["cothe_run_test.py", "--answers", path, "--operator", "T", "--auth-id", auth_id]
        try:
            core.main(); code = 0
        except SystemExit as e:
            code = e.code
        except RuntimeError as e:  # scan stub reached = gate passed
            code = "scan"
        sys.argv = old; os.unlink(path)
        return code, [p.get("content") for p in posts]

    code, msgs = run_main(make_answers(), "m-ok")
    assert code == "scan", (code, msgs)
    print("ok match passes gate (reached mocked scan)")

    def mism(ans, needle, tag):
        code, msgs = run_main(ans, tag)
        assert code == 2 and msgs and "authorization doesn't match quote" in msgs[0] and needle in msgs[0], (code, msgs)
        print("ok", tag, "->", msgs[0].splitlines()[1])

    a = make_answers(); a["client"]["email"] = "mallory@gmail.com"
    mism(a, "client email: m***@gmail.com vs quote J***@Gmail.com", "email-mismatch")
    a = make_answers(); a["client"]["contact"] = "John Smith, CEO"
    mism(a, "client name:", "name-mismatch")
    a = make_answers(); a["authorizingPerson"]["typedLegalName"] = "Bob Jones"
    mism(a, "signer:", "signer-mismatch")
    a = make_answers(); a["client"]["organization"] = "Other Co"
    mism(a, "company:", "company-mismatch")
    a = make_answers(); a["client"]["organization"] = ""
    code, _ = run_main(a, "company-blank"); assert code == "scan", code
    print("ok company skipped when blank")
    q = dict(BASE_QUOTE); q["quote_id"] = ""
    mism(make_answers(quote=q), "quote_id", "no-quote-id")

    def scope(sc, needle, tag):
        a = make_answers(); a["scope_check"] = {"answers": sc}
        code, msgs = run_main(a, tag)
        assert code == 2 and msgs and "under-covers scope" in msgs[0] and needle in msgs[0], (code, msgs)
        print("ok", tag, "->", msgs[0].splitlines()[1])
    scope({"use": "business", "devices": 14, "sites": 1}, "covers 10 devices but client listed 14", "scope-devices")
    scope({"use": "business", "devices": 5, "sites": 2}, "covers 1 site(s) but client listed 2", "scope-sites")
    q = dict(BASE_QUOTE, tierId="home", tier="Home Security Check")
    a = make_answers(quote=q)
    code, msgs = run_main(a, "scope-kind")
    assert code == 2 and "business use but quote is a home tier" in msgs[0], msgs
    print("ok scope-kind")
    q = dict(BASE_QUOTE, extraDevices=4)
    a = make_answers(quote=q); a["scope_check"] = {"answers": {"use": "business", "devices": 14, "sites": 1}}
    code, _ = run_main(a, "scope-extras"); assert code == "scan", code
    print("ok extras cover 14 devices")

    # ---- payment gate ----
    code, msgs = run_main(make_answers(), "pay-none", pay=False)
    assert code == 4 and msgs == [core.NO_PAYMENT_MSG], (code, msgs)
    print("ok no payment refused")
    payments.record_cash("pay-cash", 249, "Martin", "martin_c", "src-pay-cash", "Acme")
    code, msgs = run_main(make_answers(), "pay-cash", pay=False)
    assert code == "scan", (code, msgs)
    print("ok cash payment passes")
    assert "Run started by T" in msgs[0] and "Paid: cash $249, recorded by Martin" in msgs[0], msgs
    print("ok started msg:", msgs[0][-60:])
    rep = core.build_report({"ip": "8.8.8.8", "ports": []}, "T", "Acme", "Jane Doe", "pay-cash",
                            payments.find_payment("pay-cash"))
    assert "Paid:** cash $249, recorded by Martin" in rep
    print("ok report includes payment")
    os.environ["STRIPE_SECRET_KEY"] = ""
    assert payments.find_payment("nope") is None
    print("ok stripe skipped quietly without key")
    assert payments.parse_paid_cash("PAID CASH 249") == (True, 249.0)
    assert payments.parse_paid_cash("paid cash") == (True, None)
    assert payments.parse_paid_cash("paid cash please")[0] is False

    # ---- watcher: paid cash recorded once, only when linked to an intake auth (mock Discord) ----
    import cothe_watch_run_test as w
    w.download_answers = lambda m, d: None
    w.auth_company = lambda a: "Acme"
    w.refresh_requesters = lambda m: None
    T0 = 1558462561454657566
    sf = lambda mins: str(T0 + ((mins * 60000) << 22))
    auth = {"id": sf(0), "webhook_id": "x", "author": {"username": "COTHE Intake"},
            "attachments": [{"filename": "answers.json", "url": "u"}], "content": ""}
    pay = {"id": sf(5), "content": "Paid Cash 249", "message_reference": {"message_id": auth["id"]},
           "author": {"username": "martin_c", "global_name": "Martin"}}
    stray = {"id": sf(300), "content": "paid cash", "author": {"username": "bob"}}
    msgs = [stray, pay, auth]
    w.api_get = lambda path: msgs
    posts.clear()
    w.process(); w.process()
    pm = [p["content"] for p in posts if "Payment recorded" in (p.get("content") or "")]
    assert pm == ["💵 Payment recorded — cash $249 by Martin (@martin_c) for Acme (auth %s)" % auth["id"]], posts
    rec = payments.find_payment(auth["id"])
    assert rec["recorded_by"] == "Martin" and rec["recorded_by_username"] == "martin_c" and rec["at"]
    assert payments.find_payment(stray["id"]) is None and len([k for k in payments.load_payments() if k == auth["id"]]) == 1
    print("ok watcher records paid cash once; ignores unlinked/out-of-window")

    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
