#!/usr/bin/env python3
"""
COTHE LLC "run test" — non-destructive external assessment runner.

Given a Client internet IP + the operator (accountable person) who typed `run test`,
runs a NON-DESTRUCTIVE external scan (TCP connect port scan of common ports, light
version/banner detection, HTTP/HTTPS title if open) and posts a report to the COTHE
intake Discord channel via the intake webhook.

Safety (enforced here):
  * Non-destructive only: nmap -Pn -sT (TCP connect), --version-light, safe discovery
    scripts (http-title, ssl-cert). NO exploit scripts, NO brute force, NO -sU UPnP
    abuse, NO -A aggressive, NO NSE "intrusive"/"exploit"/"dos"/"brute" categories.
  * Requires a valid public client IP. Refuses private / reserved / loopback ranges.
  * When run from an authorization (--answers answers.json) it REQUIRES:
      signed-by name, e-signature captured, ID photo captured (or a photo_code matching a
      '📷 ID photo for request code' image message in the intake channel; needs
      COTHE_DISCORD_BOT_TOKEN), and a valid client IP.
    If any are missing it posts WHY it won't run and exits non-zero.
  * One run per authorization message id: tracked in a seen file. A second attempt
    on the same auth id is refused.

Usage:
  # From a downloaded intake answers.json (preferred; validates sig/photo/IP):
  python3 tools/cothe_run_test.py --answers answers.json --operator "Martin" \
      --auth-id 1558499999999999999

  # Manual, trusting the caller to have verified the authorization:
  python3 tools/cothe_run_test.py --ip 203.0.113.5 --operator "Martin" \
      --company "Acme Co" --signed-by "Jane Doe" --auth-id manual-2026-10-10 \
      --i-have-verified-authorization

  # Dry run (scan + build report, print instead of posting), no seen-file write:
  python3 tools/cothe_run_test.py --ip 203.0.113.5 --operator "Martin" --dry-run
"""
import argparse, datetime, ipaddress, json, os, re, subprocess, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
REPORTS = os.path.join(DATA, "reports")
SEEN = os.path.join(DATA, "seen_runs.json")
# Common ports we assess (non-destructive external surface).
TOP_PORTS = ("21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,465,587,"
             "993,995,1433,1521,1723,2049,3306,3389,5432,5900,5985,6379,8000,"
             "8008,8080,8443,8888,9000,9200,27017")
WEBHOOK = os.environ.get("COTHE_INTAKE_WEBHOOK_URL", "").strip()


def is_public_ip(v):
    try:
        ip = ipaddress.ip_address((v or "").strip())
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def load_seen():
    if os.path.exists(SEEN):
        try:
            return json.load(open(SEEN))
        except Exception:
            return {}
    return {}


def save_seen(d):
    os.makedirs(DATA, exist_ok=True)
    json.dump(d, open(SEEN, "w"), indent=2)


def post_webhook(content=None, file_path=None, file_name=None):
    if not WEBHOOK:
        print("[no COTHE_INTAKE_WEBHOOK_URL set — not posting]", file=sys.stderr)
        if content:
            print(content)
        return False
    boundary = "----cotheboundary%d" % int(datetime.datetime.now().timestamp())
    payload = {"username": "COTHE Run Test", "allowed_mentions": {"parse": []}}
    if content:
        payload["content"] = content[:1990]
    parts = []
    parts.append(b"--" + boundary.encode() + b"\r\n")
    parts.append(b'Content-Disposition: form-data; name="payload_json"\r\n')
    parts.append(b"Content-Type: application/json\r\n\r\n")
    parts.append(json.dumps(payload).encode() + b"\r\n")
    if file_path and os.path.exists(file_path):
        data = open(file_path, "rb").read()
        parts.append(b"--" + boundary.encode() + b"\r\n")
        parts.append(('Content-Disposition: form-data; name="files[0]"; filename="%s"\r\n'
                      % (file_name or os.path.basename(file_path))).encode())
        parts.append(b"Content-Type: text/markdown\r\n\r\n")
        parts.append(data + b"\r\n")
    parts.append(b"--" + boundary.encode() + b"--\r\n")
    body = b"".join(parts)
    req = urllib.request.Request(WEBHOOK, data=body, headers={
        "Content-Type": "multipart/form-data; boundary=" + boundary,
        "User-Agent": "cothe-run-test"})
    try:
        urllib.request.urlopen(req, timeout=60)
        return True
    except Exception as e:
        print("[webhook post failed: %s]" % e, file=sys.stderr)
        return False


def run_scan(ip):
    """Non-destructive external assessment. Returns dict with parsed results + raw."""
    os.makedirs(REPORTS, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    xml = os.path.join(REPORTS, "scan-%s-%s.xml" % (ip.replace(":", "_"), stamp))
    cmd = [
        "nmap",
        "-Pn",                 # no host-discovery ping (treat as up)
        "-sT",                 # TCP connect (no raw packets, non-destructive)
        "-n",                  # no DNS
        "--version-light",     # light banner/service detection only
        "-sV",
        "-p", TOP_PORTS,
        "--script", "banner,http-title,ssl-cert",  # safe discovery scripts only
        "--host-timeout", "4m",
        "--max-retries", "2",
        "-oX", xml,
        ip,
    ]
    print("[scan] " + " ".join(cmd), file=sys.stderr)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    raw = proc.stdout + ("\n" + proc.stderr if proc.stderr.strip() else "")
    ports = parse_ports(xml) if os.path.exists(xml) else []
    return {"ip": ip, "stamp": stamp, "ports": ports, "raw": raw, "xml": xml,
            "returncode": proc.returncode}


def parse_ports(xml_path):
    import xml.etree.ElementTree as ET
    out = []
    try:
        tree = ET.parse(xml_path)
    except Exception:
        return out
    for port in tree.findall(".//port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        info = {}
        if svc is not None:
            for k in ("name", "product", "version", "extrainfo", "tunnel"):
                if svc.get(k):
                    info[k] = svc.get(k)
        scripts = {}
        for s in port.findall("script"):
            scripts[s.get("id")] = (s.get("output") or "").strip()
        out.append({
            "port": int(port.get("portid")),
            "proto": port.get("protocol"),
            "service": info.get("name", ""),
            "product": " ".join(x for x in (info.get("product"), info.get("version"),
                                            info.get("extrainfo")) if x),
            "scripts": scripts,
        })
    return out


def build_report(scan, operator, company, signed_by, auth_id):
    ip = scan["ip"]
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M %Z").strip()
    lines = []
    lines.append("# COTHE LLC — External Assessment Report")
    lines.append("")
    lines.append("- **Target (Client internet IP):** `%s`" % ip)
    lines.append("- **Authorized by:** %s" % (signed_by or "—"))
    lines.append("- **Company:** %s" % (company or "—"))
    lines.append("- **Run started by (accountable):** %s" % operator)
    lines.append("- **Authorization id:** `%s`" % (auth_id or "—"))
    lines.append("- **Run at:** %s" % now)
    lines.append("- **Scan type:** Non-destructive external — TCP connect port scan of "
                 "common ports, light version/banner detection, HTTP/HTTPS title. "
                 "No exploits, no brute force, no credential guessing.")
    lines.append("")
    ports = scan["ports"]
    if not ports:
        lines.append("## Result")
        lines.append("")
        lines.append("No common TCP ports found open on `%s`. The host presents no "
                     "externally reachable services among the assessed common ports. "
                     "This is a good posture for a home/small-business edge." % ip)
    else:
        lines.append("## Open ports (%d)" % len(ports))
        lines.append("")
        lines.append("| Port | Proto | Service | Product/Version |")
        lines.append("|---|---|---|---|")
        for p in ports:
            lines.append("| %d | %s | %s | %s |" % (
                p["port"], p["proto"], p["service"] or "—",
                (p["product"] or "—").replace("|", "\\|")))
        lines.append("")
        details = []
        for p in ports:
            for sid, out in p["scripts"].items():
                if out:
                    details.append("**%d/%s — %s:**\n```\n%s\n```" % (
                        p["port"], p["proto"], sid, out[:800]))
        if details:
            lines.append("## Banners & titles")
            lines.append("")
            lines.extend(details)
            lines.append("")
        lines.append("## Observations")
        lines.append("")
        risky = {23: "Telnet (cleartext) exposed — strongly recommend disabling.",
                 21: "FTP exposed — prefer SFTP; avoid anonymous/cleartext FTP.",
                 3389: "RDP exposed to the internet — restrict to VPN / allowlist.",
                 445: "SMB exposed to the internet — should not be internet-facing.",
                 139: "NetBIOS exposed — should not be internet-facing.",
                 3306: "MySQL exposed — should be firewalled from the internet.",
                 5432: "PostgreSQL exposed — should be firewalled from the internet.",
                 6379: "Redis exposed — often unauthenticated; firewall immediately.",
                 27017: "MongoDB exposed — firewall immediately.",
                 5900: "VNC exposed — restrict to VPN / allowlist."}
        flagged = [risky[p["port"]] for p in ports if p["port"] in risky]
        if flagged:
            for f in flagged:
                lines.append("- ⚠️ " + f)
        else:
            lines.append("- No high-risk services flagged among open ports; review each "
                         "exposed service for necessity and patch level.")
    lines.append("")
    lines.append("---")
    lines.append("*Non-destructive assessment performed under signed authorization. "
                 "COTHE LLC — veteran-owned network security assessments.*")
    return "\n".join(lines)


PHOTO_MSG_RE = re.compile(r"📷\s*ID photo for request code\s+([A-Z0-9]{6})\b")
IMAGE_EXT = (".jpg", ".jpeg", ".png", ".webp", ".heic")


def photo_code_in_messages(code, messages):
    """True if a '📷 ID photo for request code CODE' message with an image attachment exists."""
    code = (code or "").strip().upper()
    if not re.fullmatch(r"[A-Z0-9]{6}", code):
        return False
    for m in messages or []:
        mm = PHOTO_MSG_RE.search(m.get("content") or "")
        if not mm or mm.group(1) != code:
            continue
        for a in m.get("attachments", []):
            ct = (a.get("content_type") or "").lower()
            fn = (a.get("filename") or "").lower()
            if ct.startswith("image/") or fn.endswith(IMAGE_EXT):
                return True
    return False


def fetch_channel_messages(pages=4):
    """Fetch recent intake-channel messages with the bot token (never printed). [] if no token."""
    token = os.environ.get("COTHE_DISCORD_BOT_TOKEN", "").strip()
    if not token:
        return []
    chan = os.environ.get("COTHE_CHANNEL_ID", "1558462561454657566")
    out, before = [], None
    for _ in range(pages):
        url = "https://discord.com/api/v10/channels/%s/messages?limit=100" % chan
        if before:
            url += "&before=" + before
        req = urllib.request.Request(url, headers={
            "Authorization": "Bot " + token,
            "User-Agent": "cothe-run-test (https://holydog413.github.io/cothe-llc, 1.0)"})
        try:
            batch = json.load(urllib.request.urlopen(req, timeout=30))
        except Exception as e:
            print("[warn] could not read intake channel for photo code: %s" % type(e).__name__, file=sys.stderr)
            break
        out.extend(batch)
        if len(batch) < 100:
            break
        before = batch[-1]["id"]
    return out


def resolve_photo(info, messages=None):
    """Mark info['photo'] True if a phone photo_code is verified in the channel."""
    if info.get("photo") or not info.get("photo_code"):
        return info
    if messages is None:
        messages = fetch_channel_messages()
    if photo_code_in_messages(info["photo_code"], messages):
        info["photo"] = True
        info["photo_via"] = "phone code %s" % info["photo_code"]
    else:
        info["photo_missing_reason"] = ("ID photo not captured and no phone photo found for code %s"
                                        % info["photo_code"])
    return info


def extract_from_answers(path):
    d = json.load(open(path))
    a = d.get("authorizingPerson", {})
    c = d.get("client", {})
    e = d.get("engagement", {})
    return {
        "ip": e.get("clientIp", ""),
        "company": c.get("organization", ""),
        "signed_by": a.get("typedLegalName", ""),
        "sig": bool(a.get("signaturePresent")),
        "photo": bool(a.get("identityPhotoPresent")),
        "photo_code": (a.get("photo_code") or "").strip().upper(),
    }


def validate_authorization(info):
    """Returns (ok, list_of_missing_reasons)."""
    missing = []
    if not info.get("signed_by"):
        missing.append("signed-by name is missing")
    if not info.get("sig"):
        missing.append("e-signature was not captured")
    if not info.get("photo"):
        missing.append(info.get("photo_missing_reason") or "ID photo was not captured")
    if not is_public_ip(info.get("ip", "")):
        missing.append("a valid public client IP is missing/invalid")
    return (len(missing) == 0, missing)


def main():
    ap = argparse.ArgumentParser(description="COTHE LLC non-destructive run-test runner")
    ap.add_argument("--operator", required=True, help="Discord name of who typed 'run test' (accountable)")
    ap.add_argument("--answers", help="Path to intake answers.json (validates sig/photo/IP)")
    ap.add_argument("--ip", help="Client internet IP (manual mode)")
    ap.add_argument("--company", default="")
    ap.add_argument("--signed-by", default="")
    ap.add_argument("--auth-id", default="", help="Authorization/Discord message id (one run per id)")
    ap.add_argument("--i-have-verified-authorization", action="store_true",
                    help="Manual mode attestation: caller confirms a valid signed authorization exists")
    ap.add_argument("--dry-run", action="store_true", help="Scan + build report, print, do not post or mark seen")
    args = ap.parse_args()

    if args.answers:
        info = resolve_photo(extract_from_answers(args.answers))
    else:
        if not args.ip:
            ap.error("provide --answers or --ip")
        info = {"ip": args.ip, "company": args.company, "signed_by": args.signed_by,
                "sig": args.i_have_verified_authorization,
                "photo": args.i_have_verified_authorization}

    # When using answers.json, always enforce the full authorization gate.
    # In manual mode, require either answers or the explicit attestation.
    if args.answers:
        ok, missing = validate_authorization(info)
    else:
        if args.i_have_verified_authorization:
            ok = is_public_ip(info["ip"])
            missing = [] if ok else ["a valid public client IP is missing/invalid"]
        else:
            ok, missing = False, ["manual mode requires --answers or --i-have-verified-authorization"]

    ip = info["ip"]
    if not ok:
        reason = "; ".join(missing)
        msg = ("⛔ **Won't run** for IP `%s` — authorization incomplete: %s. "
               "No scan was performed." % (ip or "?", reason))
        print(msg, file=sys.stderr)
        if not args.dry_run:
            post_webhook(content=msg)
        sys.exit(2)

    # Cap: one run per authorization message id.
    seen = load_seen()
    key = args.auth_id or ("ip:" + ip)
    if not args.dry_run and key in seen:
        msg = ("⛔ **Already run** for authorization `%s` (IP `%s`) at %s by %s. "
               "One run per authorization — refusing to re-scan." %
               (key, ip, seen[key].get("at"), seen[key].get("operator")))
        print(msg, file=sys.stderr)
        post_webhook(content=msg)
        sys.exit(3)

    # Announce
    start_msg = ("▶️ **Started by %s** — running a non-destructive external assessment "
                 "of Client IP `%s`%s. Authorized by %s." %
                 (args.operator, ip,
                  (" for **%s**" % info["company"]) if info.get("company") else "",
                  info.get("signed_by") or "—"))
    print(start_msg, file=sys.stderr)
    if not args.dry_run:
        post_webhook(content=start_msg)

    scan = run_scan(ip)
    report = build_report(scan, args.operator, info.get("company"),
                          info.get("signed_by"), args.auth_id)
    md_path = os.path.join(REPORTS, "report-%s-%s.md" % (ip.replace(":", "_"), scan["stamp"]))
    os.makedirs(REPORTS, exist_ok=True)
    open(md_path, "w").write(report)
    print("[report written] " + md_path, file=sys.stderr)

    nopen = len(scan["ports"])
    summary = ("✅ **Assessment complete** — IP `%s`, authorized by %s, run by %s. "
               "%d open common port(s) found. Full report attached." %
               (ip, info.get("signed_by") or "—", args.operator, nopen))
    if args.dry_run:
        print("\n===== REPORT (dry-run) =====\n")
        print(report)
        print("\n===== SUMMARY =====\n" + summary)
    else:
        post_webhook(content=summary, file_path=md_path)
        seen[key] = {"at": datetime.datetime.now().isoformat(timespec="seconds"),
                     "operator": args.operator, "ip": ip,
                     "company": info.get("company"), "report": md_path}
        save_seen(seen)
    print("done", file=sys.stderr)


if __name__ == "__main__":
    main()
