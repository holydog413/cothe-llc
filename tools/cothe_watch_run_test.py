#!/usr/bin/env python3
"""
COTHE LLC "run test" watcher.

Polls the COTHE intake Discord channel for replies that say exactly `run test`
(case-insensitive) in response to a "COTHE Intake" authorization message, then
runs the non-destructive assessment via cothe_run_test and posts the report.

Requires a Discord BOT token in env COTHE_DISCORD_BOT_TOKEN with permissions:
  View Channel + Read Message History (+ Message Content intent enabled in the
  Developer Portal). The intake webhook (COTHE_INTAKE_WEBHOOK_URL) is used to post.

Safety:
  * Only acts on a `run test` message that is a REPLY to a COTHE Intake
    authorization message (message_reference), OR that was posted within
    REPLY_WINDOW_MIN minutes after an intake message AND quotes/mentions it.
    A bare `run test` with no linked authorization is IGNORED (never scans a
    free-form IP).
  * The authorization message must carry an answers.json attachment with
    signature + ID photo captured (or photo_code matched to a phone photo msg) and a valid public client IP (enforced by
    cothe_run_test.validate_authorization).
  * One run per authorization message id (seen file in cothe_run_test).
  * Payment: a reply `paid cash [amount]` to the authorization (same linking rules as
    `run test`) records a cash payment in data/payments.json (each message once) and
    posts a confirmation. `run test` is refused until a payment exists.
  * Inside-out (LAN via Tailscale): only when the signed authorization AND the signed quote both
    request internal testing with the same valid private CIDR (cothe_run_test.validate_internal),
    and exactly one online COTHE-tailnet peer has an approved route covering it. Otherwise the
    internal part is refused with a Discord note and outside-in still runs. Only the authorized
    CIDR is ever scanned. If the client wasn't ready, a later `run internal` reply to the same
    authorization runs ONLY the internal part, once, after re-checking every gate.

  python3 tools/cothe_watch_run_test.py --help | --self-test

Run from cron every few minutes, or once:  python3 tools/cothe_watch_run_test.py
Env: COTHE_CHANNEL_ID (default 1558462561454657566), DRY_RUN=1, REPLY_WINDOW_MIN.
"""
import json, os, re, sys, tempfile, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cothe_run_test as core
import cothe_payments as payments

TOKEN = os.environ.get("COTHE_DISCORD_BOT_TOKEN", "").strip()
CHANNEL = os.environ.get("COTHE_CHANNEL_ID", "1558462561454657566")
SERVER = "1558462439979360358"
APP_ID = os.environ.get("COTHE_DISCORD_APP_ID", "<YOUR_APP_CLIENT_ID>")
REPLY_WINDOW_MIN = int(os.environ.get("REPLY_WINDOW_MIN", "180"))
DRY = os.environ.get("DRY_RUN") == "1"
RUN_TEST_RE = re.compile(r"^\s*run\s+test\s*$", re.IGNORECASE)
RUN_INTERNAL_RE = re.compile(r"^\s*run\s+internal\s*$", re.IGNORECASE)
API = "https://discord.com/api/v10"


def setup_help():
    invite = ("https://discord.com/oauth2/authorize?client_id=%s"
              "&scope=bot&permissions=66560" % APP_ID)
    print("""
COTHE_DISCORD_BOT_TOKEN is not set. The watcher needs a Discord bot to read the
channel. One-time setup:

  1. Go to https://discord.com/developers/applications  -> New Application  (name: "COTHE Run Test")
  2. Bot tab -> Add Bot. Under "Privileged Gateway Intents" enable MESSAGE CONTENT INTENT.
  3. Bot tab -> Reset Token -> copy the token.
  4. Store it ONLY in box-secrets as COTHE_DISCORD_BOT_TOKEN (never commit it).
  5. OAuth2 -> copy the Application (client) ID into COTHE_DISCORD_APP_ID, then invite the bot:
       %s
     (permissions=66560 = View Channel + Read Message History)
  6. Invite it to server %s and make sure it can see channel %s.
  7. Re-run:  python3 tools/cothe_watch_run_test.py

Until then, use the manual CLI with a downloaded answers.json:
  python3 tools/cothe_run_test.py --answers answers.json --operator "Martin" --auth-id <intake message id>
""" % (invite, SERVER, CHANNEL))


def api_get(path):
    req = urllib.request.Request(API + path, headers={
        "Authorization": "Bot " + TOKEN,
        "User-Agent": "cothe-run-test-watcher (https://holydog413.github.io/cothe-llc, 1.0)"})
    return json.load(urllib.request.urlopen(req, timeout=30))


def is_intake_auth(msg):
    """True if msg looks like a COTHE Intake authorization with answers.json."""
    author = (msg.get("author") or {})
    name = (author.get("username") or "") + " " + (msg.get("author", {}).get("global_name") or "")
    webhooky = bool(msg.get("webhook_id"))
    looks_intake = "cothe intake" in name.lower() or webhooky
    has_answers = any((a.get("filename") or "").lower() == "answers.json"
                      for a in msg.get("attachments", []))
    has_embed = any("authorization" in (e.get("title") or "").lower()
                    for e in msg.get("embeds", []))
    return (looks_intake or has_embed) and has_answers


def display_name(author):
    return (author.get("global_name") or author.get("username")
            or ("user-" + str(author.get("id"))))


def download_answers(msg, dest_dir):
    for a in msg.get("attachments", []):
        if (a.get("filename") or "").lower() == "answers.json":
            url = a["url"]
            path = os.path.join(dest_dir, "answers-%s.json" % msg["id"])
            req = urllib.request.Request(url, headers={
                "User-Agent": "cothe-run-test-watcher (https://holydog413.github.io/cothe-llc, 1.0)"})
            with urllib.request.urlopen(req, timeout=30) as r, open(path, "wb") as f:
                f.write(r.read())
            return path
    return None


REQ_STATE = os.path.join(core.DATA, "requesters_last_intake.txt")


def refresh_requesters(msgs):
    """Rebuild quote/requesters.enc.json when a new intake post appears. Fails quietly."""
    ids = [int(m["id"]) for m in msgs if is_intake_auth(m)]
    if not ids or DRY:
        return
    newest = str(max(ids))
    try:
        last = open(REQ_STATE).read().strip()
    except Exception:
        last = ""
    if newest == last:
        return
    import subprocess
    r = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "build_requesters.py")], timeout=600,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if r.returncode == 0:
        os.makedirs(core.DATA, exist_ok=True)
        open(REQ_STATE, "w").write(newest)
    else:
        print("[requesters] refresh failed (rc=%d) — continuing" % r.returncode, file=sys.stderr)


def find_auth(m, msgs, by_id):
    """Authorization this reply responds to: message_reference, else newest intake within window."""
    auth = None
    ref_id = (m.get("message_reference") or {}).get("message_id")
    if ref_id:
        auth = by_id.get(ref_id)
        if auth is None:
            try:
                auth = api_get("/channels/%s/messages/%s" % (CHANNEL, ref_id))
            except Exception:
                auth = None
    if auth is None:
        cand = [x for x in msgs if is_intake_auth(x) and int(x["id"]) < int(m["id"])]
        if cand:
            newest = max(cand, key=lambda x: int(x["id"]))
            # Discord snowflake -> ms since epoch
            dt_ms = (int(m["id"]) >> 22) - (int(newest["id"]) >> 22)
            if dt_ms <= REPLY_WINDOW_MIN * 60 * 1000:
                auth = newest
    return auth if (auth is not None and is_intake_auth(auth)) else None


def auth_company(auth):
    """Best-effort company name from the authorization's answers.json (no scan)."""
    try:
        with tempfile.TemporaryDirectory() as td:
            p = download_answers(auth, td)
            return core.extract_from_answers(p).get("company", "") if p else ""
    except Exception:
        return ""


def process_payments(msgs, by_id):
    """Record `paid cash [amount]` replies. Returns number recorded."""
    n = 0
    for m in reversed(msgs):
        is_cash, amount = payments.parse_paid_cash(m.get("content") or "")
        if not is_cash or m.get("webhook_id") or payments.is_processed(m["id"]):
            continue
        author = m.get("author") or {}
        name, user = display_name(author), author.get("username") or ""
        auth = find_auth(m, msgs, by_id)
        if auth is None:
            print("[skip] paid-cash msg %s by %s has no linked COTHE authorization — ignored"
                  % (m["id"], name), file=sys.stderr)
            continue
        company = auth_company(auth)
        if DRY:
            print("[DRY] would record cash%s by %s for auth %s"
                  % (payments.fmt_amount(amount), name, auth["id"]), file=sys.stderr)
            continue
        rec = payments.record_cash(auth["id"], amount, name, user, m["id"], company)
        if rec is None:
            continue
        who = name + (" (@%s)" % user if user and user != name else "")
        core.post_webhook(content="💵 Payment recorded — cash%s by %s for %s (auth %s)"
                          % (payments.fmt_amount(amount), who, company or "—", auth["id"]))
        n += 1
    return n


def process_run_internal(msgs, by_id):
    """`run internal` reply: internal-only follow-up for an authorization whose outside-in run
    already happened but whose internal part was skipped because Tailscale wasn't ready.
    Re-checks every gate (auth, quote, payment, internal scope, Tailscale). One per authorization."""
    n = 0
    for m in reversed(msgs):
        if not RUN_INTERNAL_RE.match(m.get("content") or "") or m.get("webhook_id"):
            continue
        operator = display_name(m.get("author") or {})
        auth = find_auth(m, msgs, by_id)
        if auth is None:
            print("[skip] run-internal msg %s has no linked authorization" % m["id"], file=sys.stderr)
            continue
        seen = core.load_seen()
        prev = seen.get(auth["id"])
        if not prev or prev.get("at") == "refused":
            continue  # outside-in must have run first (via `run test`)
        if prev.get("internal") not in ("not_ready", "error"):
            continue  # done already, not requested, or gated off by scope — nothing to retry
        if prev.get("internal_retry_msg"):
            continue  # one internal retry per authorization
        if m["id"] in (prev.get("internal_refused_msgs") or []):
            continue  # already answered this reply
        with tempfile.TemporaryDirectory() as td:
            apath = download_answers(auth, td)
            if not apath:
                continue
            info = core.extract_from_answers(apath)
            if not info.get("photo") and info.get("photo_code"):
                info = core.resolve_photo(info, msgs if core.photo_code_in_messages(info["photo_code"], msgs)
                                          else core.fetch_channel_messages())
            ok, missing = core.validate_authorization(info)
            payment = payments.find_payment(auth["id"])
            if not ok or not payment:
                print("[skip] run-internal for %s: gates failed" % auth["id"], file=sys.stderr)
                continue
            internal = core.run_internal(info, dry_run=DRY)
            if DRY:
                print("[DRY] run internal for %s: %s" % (auth["id"], core.internal_discord_line(internal)))
                continue
            if internal["status"] in ("not_ready", "refused"):
                core.post_webhook(content="(requested by %s) " % operator + core.internal_discord_line(internal))
                seen = core.load_seen()
                seen[auth["id"]].setdefault("internal_refused_msgs", []).append(m["id"])
                core.save_seen(seen)
                continue  # retry not consumed: client finishes setup, rep replies `run internal` again
            ip = info.get("ip")
            scan = {"ip": ip, "ports": [], "stamp": core.datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
                    "skipped": True}
            report = core.build_report(scan, operator, info.get("company"), info.get("signed_by"),
                                       auth["id"], payment, internal)
            report = report.replace("## 1. Outside-in findings (internet view)\n",
                                    "## 1. Outside-in findings (internet view)\n\nSee the earlier report for this "
                                    "authorization (%s). This follow-up covers the inside-out part only.\n<!--" %
                                    os.path.basename(prev.get("report") or "—"), 1).replace(
                                    "\n## 2. Inside-out", "-->\n## 2. Inside-out", 1)
            md = os.path.join(core.REPORTS, "report-internal-%s-%s.md" % (auth["id"], scan["stamp"]))
            os.makedirs(core.REPORTS, exist_ok=True)
            open(md, "w").write(report)
            core.post_webhook(content="✅ **Inside-out follow-up complete** (run by %s) — %s Report attached."
                              % (operator, core.internal_discord_line(internal)), file_path=md)
            seen = core.load_seen()
            seen[auth["id"]].update({"internal": internal["status"], "internal_cidr": internal.get("cidr", ""),
                                     "internal_retry_msg": m["id"], "internal_report": md})
            core.save_seen(seen)
            n += 1
    return n


def self_test():
    """Offline self-test: gate logic on synthetic answers + a direct scan of 127.0.0.1 only."""
    q = {"tier": "Home Security Check", "tierId": "home", "lines": ["Home Security Check: $249.00"],
         "internal": True, "internalCidr": "192.168.1.0/24", "internalNotes": "always-on PC available for Tailscale"}
    base = {"quote": q, "internal_requested": True, "internal_cidr": "192.168.1.0/24", "internal_raw": "192.168.1.0/24"}
    cases = [("both requested, same CIDR", base, "ok"),
             ("auth not checked", dict(base, internal_requested=False), "refused"),
             ("quote lacks internal", dict(base, quote=dict(q, internal=False)), "refused"),
             ("CIDR mismatch", dict(base, internal_cidr="192.168.2.0/24"), "refused"),
             ("public CIDR", dict(base, internal_cidr=core.internal_scan.norm_cidrs("8.8.8.0/24")), "refused"),
             ("neither", {"quote": dict(q, internal=False)}, "not_requested")]
    bad = 0
    for name, info, want in cases:
        got = core.validate_internal(info)[0]
        print("[self-test] %-28s -> %-13s %s" % (name, got, "ok" if got == want else "FAIL (want %s)" % want))
        bad += got != want
    h_old = core.quote_hash(dict(q, internal=False))
    print("[self-test] hash differs when internal added:", core.quote_hash(q) != h_old)
    print("[self-test] tailscale readiness:", core.internal_scan.tailscale_readiness("192.168.1.0/24")[1] or "ready")
    r = core.internal_scan.scan_internal("", via="direct", self_test=True)
    print("[self-test] localhost-only scan (SELF-TEST, not a client): %d host(s), ports %s"
          % (len(r["hosts"]), [p["port"] for v in r["hosts"].values() for p in v]))
    it = {"status": "done", "cidr": "127.0.0.1/32 (self-test)", "peer": {"host": "self-test"}, "result": r,
          "findings": core.internal_scan.findings(r)}
    print("\n".join(core.internal_report_lines(it)))
    return 1 if bad else 0


def process():
    if not TOKEN:
        setup_help()
        return 1
    seen = core.load_seen()
    msgs = api_get("/channels/%s/messages?limit=50" % CHANNEL)
    # oldest first
    by_id = {m["id"]: m for m in msgs}
    handled = 0
    try:
        process_payments(msgs, by_id)
    except Exception as ex:
        print("[payments] error: %s" % type(ex).__name__, file=sys.stderr)
    for m in reversed(msgs):
        if not RUN_TEST_RE.match(m.get("content") or ""):
            continue
        operator = display_name(m.get("author") or {})
        auth = find_auth(m, msgs, by_id)
        if auth is None or not is_intake_auth(auth):
            print("[skip] run-test msg %s by %s has no linked COTHE authorization — ignored"
                  % (m["id"], operator), file=sys.stderr)
            continue
        if auth["id"] in seen:
            print("[skip] auth %s already run" % auth["id"], file=sys.stderr)
            continue
        with tempfile.TemporaryDirectory() as td:
            apath = download_answers(auth, td)
            if not apath:
                print("[skip] auth %s has no answers.json" % auth["id"], file=sys.stderr)
                continue
            info = core.extract_from_answers(apath)
            if not info.get("photo") and info.get("photo_code"):
                chan_msgs = msgs if core.photo_code_in_messages(info["photo_code"], msgs) \
                    else core.fetch_channel_messages()
                info = core.resolve_photo(info, chan_msgs)
            ok, missing = core.validate_authorization(info)
            if not ok:
                reason = "; ".join(missing)
                qr = core.validate_quote(info)
                if qr:
                    msg_out = ("⛔ **Won't run — quote not approved/signed** (requested by %s) — "
                               "authorization `%s`: %s. No scan performed."
                               % (operator, auth["id"], reason))
                else:
                    msg_out = ("⛔ **Won't run** (requested by %s) — authorization `%s` incomplete: "
                               "%s. No scan performed." % (operator, auth["id"], reason))
                print(msg_out, file=sys.stderr)
                if not DRY:
                    core.post_webhook(content=msg_out)
                    seen = core.load_seen()
                    seen[auth["id"]] = {"at": "refused", "operator": operator,
                                        "ip": info.get("ip"), "reason": reason}
                    core.save_seen(seen)
                continue
            payment = payments.find_payment(auth["id"])
            if not payment:
                print(core.NO_PAYMENT_MSG, file=sys.stderr)
                if not DRY and payments.mark_nopay_notified(m["id"]):
                    core.post_webhook(content=core.NO_PAYMENT_MSG + " (auth `%s`)" % auth["id"])
                continue  # not marked seen: can run once payment is recorded
            # Announce + scan + report (reuse core logic).
            start = ("▶️ **Started by %s** — non-destructive external assessment of Client IP "
                     "`%s`%s. Authorized by %s." % (operator, info["ip"],
                     (" for **%s**" % info["company"]) if info.get("company") else "",
                     info.get("signed_by") or "—"))
            start += " Run started by %s. Paid: %s." % (operator, payments.describe(payment))
            ist, idet = core.validate_internal(info)
            start += {"not_requested": " Inside-out: not requested.",
                      "ok": " Inside-out: requested for LAN `%s` (checking Tailscale)." % idet,
                      "refused": " Inside-out: requested but gated off — %s." % idet}[ist]
            print(start, file=sys.stderr)
            if DRY:
                print("[DRY] would scan %s for auth %s; internal: %s"
                      % (info["ip"], auth["id"], core.internal_discord_line(core.run_internal(info, dry_run=True))))
                continue
            core.post_webhook(content=start)
            scan = core.run_scan(info["ip"])
            internal = core.run_internal(info)
            report = core.build_report(scan, operator, info.get("company"),
                                       info.get("signed_by"), auth["id"], payment, internal)
            core.os.makedirs(core.REPORTS, exist_ok=True)
            md = os.path.join(core.REPORTS, "report-%s-%s.md"
                              % (info["ip"].replace(":", "_"), scan["stamp"]))
            open(md, "w").write(report)
            summary = ("✅ **Assessment complete** — IP `%s`, authorized by %s, run by %s. "
                       "%d open common port(s). Report attached.\n%s"
                       % (info["ip"], info.get("signed_by") or "—", operator, len(scan["ports"]),
                          core.internal_discord_line(internal)))
            core.post_webhook(content=summary, file_path=md)
            seen = core.load_seen()
            seen[auth["id"]] = {"at": core.datetime.datetime.now().isoformat(timespec="seconds"),
                                "operator": operator, "ip": info["ip"],
                                "company": info.get("company"), "report": md,
                                "internal": internal.get("status"), "internal_cidr": internal.get("cidr", "")}
            core.save_seen(seen)
            handled += 1
    try:
        handled += process_run_internal(msgs, by_id)
    except Exception as ex:
        print("[run-internal] error: %s" % type(ex).__name__, file=sys.stderr)
    try:
        refresh_requesters(msgs)
    except Exception as ex:  # never block run-test gating
        print("[requesters] refresh skipped: %s" % type(ex).__name__, file=sys.stderr)
    print("watcher done — %d assessment(s) run" % handled, file=sys.stderr)
    return 0


if __name__ == "__main__":
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__); sys.exit(0)
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    sys.exit(process())
