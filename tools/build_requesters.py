#!/usr/bin/env python3
"""
Build quote/requesters.enc.json: the encrypted list of clients who posted a COTHE
Intake authorization request in Discord. Used by the quote builder's
"Pick a requester" dropdown.

Reads channel COTHE_CHANNEL_ID with COTHE_DISCORD_BOT_TOKEN, downloads each intake
answers.json, dedupes by email (newest wins), and encrypts the JSON list with the
same AES-GCM / PBKDF2-SHA256 (600k) scheme + COTHE_SALES_PASSWORD as the quote
builder. Plaintext PII is never written to disk. Commits + pushes only when the
decrypted content changed (NO_PUSH=1 to skip push, NO_COMMIT=1 to skip git).
Options: --from-json FILE (use a local list instead of Discord, for tests).
Exit 0 on success / no change; non-zero on error. Secrets are never printed.
"""
import base64, hashlib, json, os, subprocess, sys, tempfile, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "quote", "requesters.enc.json")
CHANNEL = os.environ.get("COTHE_CHANNEL_ID", "1558462561454657566")
API = "https://discord.com/api/v10"
UA = "cothe-run-test-watcher (https://holydog413.github.io/cothe-llc, 1.0)"
ITER = 600000
DISCORD_EPOCH = 1420070400000


def _get(url, auth=True):
    h = {"User-Agent": UA}
    if auth:
        h["Authorization"] = "Bot " + os.environ["COTHE_DISCORD_BOT_TOKEN"].strip()
    with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=30) as r:
        return r.read()


def fetch_all_messages(max_pages=40):
    msgs, before = [], None
    for _ in range(max_pages):
        q = "/channels/%s/messages?limit=100" % CHANNEL + ("&before=%s" % before if before else "")
        page = json.loads(_get(API + q))
        if not page:
            break
        msgs.extend(page)
        before = page[-1]["id"]
        if len(page) < 100:
            break
    return msgs


def is_intake(m):
    sys.path.insert(0, HERE)
    from cothe_watch_run_test import is_intake_auth
    return is_intake_auth(m)


def snowflake_iso(mid):
    import datetime
    ms = (int(mid) >> 22) + DISCORD_EPOCH
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).isoformat(timespec="seconds")


def to_int(v):
    try:
        return max(0, int(round(float(v))))
    except Exception:
        return 0


def record(mid, d):
    c, e = d.get("client") or {}, d.get("engagement") or {}
    sc = d.get("scope_check") if isinstance(d.get("scope_check"), dict) else {}
    ans = sc.get("answers") or {}
    q = d.get("quote") if isinstance(d.get("quote"), dict) else {}
    return {
        "message_id": str(mid), "date": snowflake_iso(mid),
        "name": (c.get("contact") or (d.get("authorizingPerson") or {}).get("typedLegalName") or "").strip(),
        "email": (c.get("email") or "").strip(), "company": (c.get("organization") or "").strip(),
        "phone": (c.get("phone") or "").strip(), "address": (c.get("address") or "").strip(),
        "client_ip": (e.get("clientIp") or "").strip(),
        "use": ans.get("use") if ans.get("use") in ("home", "business") else "",
        "devices": to_int(ans.get("devices")), "sites": max(1, to_int(ans.get("sites")) or 1),
        "wifi": ans.get("wifi") or "",
        "quote_id": q.get("quote_id") or "", "quote_approved": bool(d.get("quote_approved")),
    }


def collect(msgs):
    out = {}
    for m in sorted(msgs, key=lambda x: int(x["id"])):  # oldest first; newer overwrite
        if not is_intake(m):
            continue
        a = next(a for a in m["attachments"] if (a.get("filename") or "").lower() == "answers.json")
        try:
            d = json.loads(_get(a["url"], auth=False))
        except Exception as ex:
            print("[requesters] skip %s: %s" % (m["id"], type(ex).__name__), file=sys.stderr)
            continue
        r = record(m["id"], d)
        key = r["email"].lower() or ("msg:" + r["message_id"])
        out[key] = r
    return sorted(out.values(), key=lambda r: r["date"], reverse=True)


def _key(pw, salt):
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, ITER).derive(pw.encode())


def encrypt(obj, pw):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(_key(pw, salt)).encrypt(iv, json.dumps(obj, ensure_ascii=False).encode(), None)
    b = lambda x: base64.b64encode(x).decode()
    return {"v": 1, "kdf": "PBKDF2-SHA256", "iter": ITER, "salt": b(salt), "iv": b(iv), "ct": b(ct)}


def decrypt(blob, pw):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    d = base64.b64decode
    return json.loads(AESGCM(_key(pw, d(blob["salt"]))).decrypt(d(blob["iv"]), d(blob["ct"]), None))


def main(argv):
    pw = os.environ.get("COTHE_SALES_PASSWORD")
    if not pw:
        print("COTHE_SALES_PASSWORD not set", file=sys.stderr); return 2
    if "--from-json" in argv:
        items = json.load(open(argv[argv.index("--from-json") + 1]))
    else:
        if not os.environ.get("COTHE_DISCORD_BOT_TOKEN", "").strip():
            print("COTHE_DISCORD_BOT_TOKEN not set", file=sys.stderr); return 2
        items = collect(fetch_all_messages())
    print("[requesters] %d requester(s)" % len(items), file=sys.stderr)
    try:
        if decrypt(json.load(open(OUT)), pw) == items:
            print("[requesters] unchanged", file=sys.stderr); return 0
    except Exception:
        pass
    tmp = OUT + ".tmp"
    json.dump(encrypt(items, pw), open(tmp, "w")); os.replace(tmp, OUT)
    if os.environ.get("NO_COMMIT"):
        return 0
    g = lambda *a: subprocess.run(["git", "-C", ROOT] + list(a), check=True)
    g("add", "quote/requesters.enc.json")
    if subprocess.run(["git", "-C", ROOT, "diff", "--cached", "--quiet"]).returncode == 0:
        return 0
    g("commit", "-q", "-m", "Update encrypted requester list", "--", "quote/requesters.enc.json")
    if not os.environ.get("NO_PUSH"):
        g("pull", "-q", "--rebase", "--autostash"); g("push", "-q")
    print("[requesters] updated", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
