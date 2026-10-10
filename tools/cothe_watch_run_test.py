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

Run from cron every few minutes, or once:  python3 tools/cothe_watch_run_test.py
Env: COTHE_CHANNEL_ID (default 1558462561454657566), DRY_RUN=1, REPLY_WINDOW_MIN.
"""
import json, os, re, sys, tempfile, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cothe_run_test as core

TOKEN = os.environ.get("COTHE_DISCORD_BOT_TOKEN", "").strip()
CHANNEL = os.environ.get("COTHE_CHANNEL_ID", "1558462561454657566")
SERVER = "1558462439979360358"
APP_ID = os.environ.get("COTHE_DISCORD_APP_ID", "<YOUR_APP_CLIENT_ID>")
REPLY_WINDOW_MIN = int(os.environ.get("REPLY_WINDOW_MIN", "180"))
DRY = os.environ.get("DRY_RUN") == "1"
RUN_TEST_RE = re.compile(r"^\s*run\s+test\s*$", re.IGNORECASE)
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


def process():
    if not TOKEN:
        setup_help()
        return 1
    seen = core.load_seen()
    msgs = api_get("/channels/%s/messages?limit=50" % CHANNEL)
    # oldest first
    by_id = {m["id"]: m for m in msgs}
    handled = 0
    for m in reversed(msgs):
        if not RUN_TEST_RE.match(m.get("content") or ""):
            continue
        operator = display_name(m.get("author") or {})
        # Find the authorization this run-test responds to.
        auth = None
        ref = m.get("message_reference") or {}
        ref_id = ref.get("message_id")
        if ref_id:
            auth = by_id.get(ref_id)
            if auth is None:
                try:
                    auth = api_get("/channels/%s/messages/%s" % (CHANNEL, ref_id))
                except Exception:
                    auth = None
        if auth is None:
            # Fallback: most recent intake message shortly before this one.
            cand = [x for x in msgs if is_intake_auth(x) and int(x["id"]) < int(m["id"])]
            if cand:
                newest = max(cand, key=lambda x: int(x["id"]))
                # Discord snowflake -> ms since epoch
                dt_ms = (int(m["id"]) >> 22) - (int(newest["id"]) >> 22)
                if dt_ms <= REPLY_WINDOW_MIN * 60 * 1000:
                    auth = newest
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
            # Announce + scan + report (reuse core logic).
            start = ("▶️ **Started by %s** — non-destructive external assessment of Client IP "
                     "`%s`%s. Authorized by %s." % (operator, info["ip"],
                     (" for **%s**" % info["company"]) if info.get("company") else "",
                     info.get("signed_by") or "—"))
            print(start, file=sys.stderr)
            if DRY:
                print("[DRY] would scan %s for auth %s" % (info["ip"], auth["id"]))
                continue
            core.post_webhook(content=start)
            scan = core.run_scan(info["ip"])
            report = core.build_report(scan, operator, info.get("company"),
                                       info.get("signed_by"), auth["id"])
            core.os.makedirs(core.REPORTS, exist_ok=True)
            md = os.path.join(core.REPORTS, "report-%s-%s.md"
                              % (info["ip"].replace(":", "_"), scan["stamp"]))
            open(md, "w").write(report)
            summary = ("✅ **Assessment complete** — IP `%s`, authorized by %s, run by %s. "
                       "%d open common port(s). Report attached."
                       % (info["ip"], info.get("signed_by") or "—", operator, len(scan["ports"])))
            core.post_webhook(content=summary, file_path=md)
            seen = core.load_seen()
            seen[auth["id"]] = {"at": core.datetime.datetime.now().isoformat(timespec="seconds"),
                                "operator": operator, "ip": info["ip"],
                                "company": info.get("company"), "report": md}
            core.save_seen(seen)
            handled += 1
    try:
        refresh_requesters(msgs)
    except Exception as ex:  # never block run-test gating
        print("[requesters] refresh skipped: %s" % type(ex).__name__, file=sys.stderr)
    print("watcher done — %d assessment(s) run" % handled, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(process())
