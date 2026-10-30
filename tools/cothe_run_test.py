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
      COTHE_DISCORD_BOT_TOKEN), a valid client IP, and an APPROVED + SIGNED quote
      (base service, quote_approved, quote_approved_by, quote_signature_captured,
      quote_hash == SHA-256 of canonical line items + totals).
    If any are missing it posts WHY it won't run and exits non-zero.
  * Payment gate: a payment (cash via `paid cash` reply, or Stripe when configured)
    must be recorded for the authorization id (see cothe_payments.py).
  * One run per authorization message id: tracked in a seen file. A second attempt
    on the same auth id is refused.

Internal ("inside-out") mode (--internal):
  * Must be run from a machine INSIDE the client network (on-site laptop or plug-in
    scan device). Refuses unless this host has an interface address inside one of the
    authorized ranges.
  * Targets ONLY the client-authorized private ranges (engagement.internalRanges with
    engagement.internalTesting=true, or --ranges in manual mode). Private RFC1918 IPv4
    only, each /22 or smaller. Same non-destructive nmap profile (TCP connect, light
    version detection, safe scripts) plus a ping/ARP host-discovery pass.
  * Same signature / photo / quote / payment gates. Tracked separately in the seen file
    (key "<auth-id>:internal") so one external + one internal run per authorization.
  Example (on-site):  python3 tools/cothe_run_test.py --internal --answers answers.json \
      --operator "Martin" --auth-id 1558499999999999999

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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cothe_payments as payments
import cothe_internal_scan as internal_scan

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
if not WEBHOOK:
    try:
        import json as _j
        import re as _re
        _cfg = open(os.path.join(ROOT, "authorize", "intake-config.js")).read()
        _m = _re.search(r"https://discord(?:app)?\.com/api/webhooks/[\w/-]+", _cfg)
        WEBHOOK = _m.group(0) if _m else ""
    except Exception:
        WEBHOOK = ""


def is_public_ip(v):
    try:
        ip = ipaddress.ip_address((v or "").strip())
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_multicast or ip.is_reserved or ip.is_unspecified)


MAX_INTERNAL_PREFIX = 22  # largest allowed internal range (1024 addresses)


def parse_internal_ranges(v):
    """Returns (networks, errors). Private IPv4 only, each /22 or smaller."""
    nets, errs = [], []
    for r in re.split(r"[\s,;]+", (v or "").strip()):
        if not r:
            continue
        try:
            n = ipaddress.ip_network(r, strict=False)
        except ValueError:
            errs.append("'%s' is not a valid range" % r)
            continue
        if n.version != 4 or not n.is_private or n.is_loopback or n.is_link_local or n.is_multicast:
            errs.append("'%s' is not a private (RFC1918) IPv4 range" % r)
        elif n.prefixlen < MAX_INTERNAL_PREFIX:
            errs.append("'%s' is larger than /%d" % (r, MAX_INTERNAL_PREFIX))
        else:
            nets.append(n)
    if not nets and not errs:
        errs.append("no internal ranges were authorized")
    return nets, errs


def local_ipv4_addresses():
    addrs = set()
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True,
                             text=True, timeout=10).stdout
        for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)", out):
            addrs.add(ipaddress.ip_address(m.group(1)))
    except Exception:
        pass
    if not addrs:
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.0.2.1", 9))
            addrs.add(ipaddress.ip_address(s.getsockname()[0]))
            s.close()
        except Exception:
            pass
    return addrs


def host_inside(nets):
    return any(a in n for a in local_ipv4_addresses() for n in nets)


def run_internal_scan(nets):
    os.makedirs(REPORTS, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    label = "internal-" + "_".join(str(n).replace("/", "-") for n in nets)[:80]
    xml = os.path.join(REPORTS, "scan-%s-%s.xml" % (label, stamp))
    cmd = ["nmap", "-sT", "-n", "--version-light", "-sV", "-p", TOP_PORTS,
           "--script", "banner,http-title,ssl-cert", "--host-timeout", "4m",
           "--max-retries", "2", "-T3", "--open", "-oX", xml] + [str(n) for n in nets]
    print("[scan] " + " ".join(cmd), file=sys.stderr)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    raw = proc.stdout + ("\n" + proc.stderr if proc.stderr.strip() else "")
    hosts = parse_hosts(xml) if os.path.exists(xml) else []
    return {"ip": ", ".join(str(n) for n in nets), "label": label, "stamp": stamp,
            "hosts": hosts, "ports": [p for h in hosts for p in h["ports"]],
            "raw": raw, "xml": xml, "returncode": proc.returncode}


def parse_hosts(xml_path):
    import xml.etree.ElementTree as ET
    hosts = []
    try:
        root = ET.parse(xml_path).getroot()
    except Exception:
        return hosts
    for h in root.findall("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        addr = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") == "ipv4"), "?")
        mac = next((a for a in h.findall("address") if a.get("addrtype") == "mac"), None)
        ports = []
        for p in h.findall("ports/port"):
            s = p.find("state")
            if s is None or s.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append({"host": addr, "port": p.get("portid"), "proto": p.get("protocol"),
                          "service": (svc.get("name") if svc is not None else "") or "",
                          "product": " ".join(x for x in [svc.get("product", ""), svc.get("version", "")] if x) if svc is not None else ""})
        hosts.append({"ip": addr, "mac": mac.get("addr") if mac is not None else "",
                      "vendor": mac.get("vendor", "") if mac is not None else "", "ports": ports})
    return hosts


RISKY_INTERNAL = {"23": "Telnet (cleartext admin)", "21": "FTP (cleartext)", "445": "SMB file sharing",
                  "139": "NetBIOS/SMB", "3389": "Remote Desktop", "5900": "VNC remote control",
                  "161": "SNMP", "6379": "Redis (often no auth)", "9200": "Elasticsearch",
                  "27017": "MongoDB", "2049": "NFS", "3306": "MySQL", "5432": "PostgreSQL",
                  "1433": "MS SQL"}


def build_internal_report(scan, operator, company, signed_by, auth_id, payment=None, access=""):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M %Z").strip()
    L = ["# COTHE LLC — Internal (Inside-Out) Assessment Report", "",
         "- **Target (authorized internal ranges):** `%s`" % scan["ip"],
         "- **Authorized by:** %s" % (signed_by or "—"),
         "- **Company:** %s" % (company or "—"),
         "- **Run started by (accountable):** %s" % operator]
    if access:
        L.append("- **Access method:** %s" % ("client-installed scan device" if access == "device" else "on-site visit"))
    if payment:
        L.append("- **Paid:** %s" % payments.describe(payment))
    L += ["- **Authorization id:** `%s`" % (auth_id or "—"), "- **Run at:** %s" % now,
          "- **Scan type:** Non-destructive internal — host discovery, TCP connect scan of common "
          "ports, light version/banner detection, HTTP/HTTPS title. No exploits, brute force, or "
          "intrusive scripts.", "",
          "## Summary", "",
          "- Live devices found: **%d**" % len(scan["hosts"]),
          "- Open common ports (all devices): **%d**" % len(scan["ports"]), ""]
    risky = [p for p in scan["ports"] if p["port"] in RISKY_INTERNAL]
    L += ["## Priority findings", ""]
    if risky:
        for p in risky:
            L.append("- `%s:%s` — %s. Confirm it's needed; restrict to admin devices or disable."
                     % (p["host"], p["port"], RISKY_INTERNAL[p["port"]]))
    else:
        L.append("- No high-risk services from our watch list were found on common ports.")
    L += ["", "## Devices", "", "| Device IP | MAC / vendor | Open ports |", "|---|---|---|"]
    for h in scan["hosts"]:
        ports = ", ".join("%s/%s %s" % (p["port"], p["proto"], (p["service"] + (" (" + p["product"] + ")" if p["product"] else "")).strip()) for p in h["ports"]) or "none on common ports"
        L.append("| `%s` | %s | %s |" % (h["ip"], (h["mac"] + (" " + h["vendor"] if h["vendor"] else "")).strip() or "—", ports))
    L += ["", "## Recommended next steps", "",
          "1. Disable or firewall any service above you don't recognize or need.",
          "2. Put cameras, smart-home, and guest devices on a separate VLAN / guest network.",
          "3. Change default passwords on printers, cameras, NAS, and routers; update firmware.",
          "4. Turn off SMB/RDP/VNC on machines that don't need to share or be remotely controlled.",
          ""] + removal_checklist_lines() + [
          "_Report for the Client's internal use. Scope limited to the authorized ranges and window._"]
    return "\n".join(L) + "\n"


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


NO_PAYMENT_MSG = ("⛔ Won't run — no payment recorded. Reply `paid cash` (or pay via Stripe) first.")


def build_report(scan, operator, company, signed_by, auth_id, payment=None, internal=None):
    ip = scan["ip"]
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M %Z").strip()
    lines = []
    lines.append("# COTHE LLC — Network Assessment Report")
    lines.append("")
    lines.append("- **Target (Client internet IP):** `%s`" % ip)
    lines.append("- **Authorized by:** %s" % (signed_by or "—"))
    lines.append("- **Company:** %s" % (company or "—"))
    lines.append("- **Run started by (accountable):** %s" % operator)
    if payment:
        lines.append("- **Paid:** %s" % payments.describe(payment))
    lines.append("- **Authorization id:** `%s`" % (auth_id or "—"))
    lines.append("- **Run at:** %s" % now)
    lines.append("- **Scan type:** Non-destructive external — TCP connect port scan of "
                 "common ports, light version/banner detection, HTTP/HTTPS title. "
                 "No exploits, no brute force, no credential guessing.")
    lines.append("")
    lines.append("## 1. Outside-in findings (internet view)")
    lines.append("")
    _out_start = len(lines)
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
    for _i in range(_out_start, len(lines)):
        if lines[_i].startswith("## "):
            lines[_i] = "#" + lines[_i]
    lines.append("")
    lines.extend(internal_report_lines(internal))
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


def _money(v):
    from decimal import Decimal, ROUND_HALF_UP
    try:
        return str(Decimal(float(v or 0)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    except Exception:
        return "0.00"


def _int(v):
    try:
        return max(0, int(round(float(v or 0))))
    except Exception:
        return 0


def quote_canonical(q):
    """Canonical JSON of quote line items + totals (must match authorize/index.html quoteCanonical)."""
    from decimal import Decimal, ROUND_HALF_UP
    try:
        rate = str(Decimal(float(q.get("taxRate") or 0)).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP))
    except Exception:
        rate = "0.0000"
    obj = {
        "tier": str(q.get("tier") or ""),
        "lines": [str(x) for x in (q.get("lines") or [])],
        "subtotal": _money(q.get("subtotal")),
        "discountAmt": _money(q.get("discountAmt")),
        "taxable": _money(q.get("taxable")),
        "taxRate": rate,
        "tax": _money(q.get("tax")),
        "oneTimeTotal": _money(q.get("oneTimeTotal")),
        "monitoring": str(q.get("monitoring") or ""),
        "monthly": _money(q.get("monthly")),
        "monthlyTax": _money(q.get("monthlyTax")),
        "monthlyTotal": _money(q.get("monthlyTotal")),
        "salesRep": str(q.get("salesRep") or ""),
        "clientName": str(q.get("clientName") or "").strip(),
        "clientEmail": str(q.get("clientEmail") or "").strip(),
        "clientCompany": str(q.get("clientCompany") or "").strip(),
        "tierId": str(q.get("tierId") or ""),
        "extraDevices": _int(q.get("extraDevices")),
        "extraSites": _int(q.get("extraSites")),
    }
    # Internal (inside-out) keys only when ordered, so older signed quotes keep their hash.
    if q.get("internal"):
        obj["internal"] = True
        obj["internalCidr"] = internal_scan.norm_cidrs(q.get("internalCidr"))
        obj["internalNotes"] = str(q.get("internalNotes") or "")
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def quote_hash(q):
    import hashlib
    return hashlib.sha256(quote_canonical(q).encode("utf-8")).hexdigest()


def validate_quote(info):
    """Returns list of reasons the quote gate fails (empty = OK)."""
    r = []
    q = info.get("quote")
    if not isinstance(q, dict):
        return ["no quote attached"]
    if not str(q.get("tier") or "").strip() or str(q.get("tier")).strip().lower() == "none":
        r.append("quote has no base service")
    if info.get("quote_approved") is not True:
        r.append("quote not approved by client")
    if not str(info.get("quote_approved_by") or "").strip():
        r.append("quote approver name missing")
    if info.get("quote_signature_captured") is not True:
        r.append("quote signature not captured")
    h = str(info.get("quote_hash") or "").strip().lower()
    if not h:
        r.append("quote_hash missing")
    elif h != quote_hash(q):
        r.append("quote_hash mismatch (quote items/totals were altered)")
    return r


def _norm_name(v):
    return " ".join(str(v or "").split()).lower()


def _norm_email(v):
    return str(v or "").strip().lower()


def _contact_name_matches(contact, name):
    c, n = _norm_name(contact), _norm_name(name)
    if not n:
        return False
    if c == n:
        return True
    # allow "Jane Doe, Owner" / "Jane Doe - Owner" (contact field holds name & title)
    if not c.startswith(n):
        return False
    return re.match(r"^\s*[,\-\u2013\u2014(|]", c[len(n):]) is not None


def mask_email(v):
    v = str(v or "").strip()
    if not v:
        return "(blank)"
    if "@" not in v:
        return v[:1] + "***"
    local, dom = v.split("@", 1)
    return local[:1] + "***@" + dom


def _shown(v):
    v = str(v or "").strip()
    return ('"%s"' % v) if v else "(blank)"


def validate_quote_match(info):
    """Independently recompute authorization-vs-quote consistency (ignores client-sent quote_match).
    Returns list of mismatch strings (empty = OK)."""
    q = info.get("quote")
    if not isinstance(q, dict):
        return ["quote: no quote attached"]
    r = []
    if not str(q.get("quote_id") or "").strip():
        r.append("quote_id: missing from quote")
    ae, qe = info.get("client_email", ""), q.get("clientEmail", "")
    if not _norm_email(qe) or _norm_email(ae) != _norm_email(qe):
        r.append("client email: %s vs quote %s" % (mask_email(ae), mask_email(qe)))
    an, qn = info.get("client_contact", ""), q.get("clientName", "")
    if not _contact_name_matches(an, qn):
        r.append("client name: %s vs quote %s" % (_shown(an), _shown(qn)))
    sn, qa = info.get("signed_by", ""), info.get("quote_approved_by", "")
    if not _norm_name(qa) or _norm_name(sn) != _norm_name(qa):
        r.append("signer: %s vs quote approver %s" % (_shown(sn), _shown(qa)))
    ac, qc = info.get("company", ""), q.get("clientCompany", "")
    if _norm_name(ac) and _norm_name(qc) and _norm_name(ac) != _norm_name(qc):
        r.append("company: %s vs quote %s" % (_shown(ac), _shown(qc)))
    return r


# Base tiers (must match quote builder PRICING). max_devices None = no device cap.
TIERS = {
    "home":   {"kind": "home", "max_devices": None},
    "remote": {"kind": "home", "max_devices": None},
    "smb":    {"kind": "business", "max_devices": 10},
    "smbp":   {"kind": "business", "max_devices": 25},
}


def validate_scope(info):
    """Independently recompute scope (client answers) vs quote coverage.
    Returns list of under-coverage reasons (empty = OK)."""
    q, sc = info.get("quote"), info.get("scope") or {}
    if not isinstance(q, dict):
        return []
    use = str(sc.get("use") or "").strip().lower()
    if use not in ("home", "business"):
        return ["scope answers missing (Home or Business, devices, sites)"]
    devices, sites = _int(sc.get("devices")), max(1, _int(sc.get("sites")))
    tid = str(q.get("tierId") or "")
    t = TIERS.get(tid)
    if not t:
        return ["quote has no recognizable base tier (tierId %s) — rep must re-issue quote" % _shown(tid)]
    r = []
    if use == "business" and t["kind"] == "home":
        r.append("business use but quote is a home tier")
    if t["max_devices"] is not None:
        cov = t["max_devices"] + _int(q.get("extraDevices"))
        if devices > cov:
            r.append("quote covers %d devices but client listed %d" % (cov, devices))
    cov_s = 1 + _int(q.get("extraSites"))
    if sites > cov_s:
        r.append("quote covers %d site(s) but client listed %d" % (cov_s, sites))
    return r


def extract_from_answers(path):
    d = json.load(open(path))
    a = d.get("authorizingPerson", {})
    c = d.get("client", {})
    e = d.get("engagement", {})
    return {
        "ip": e.get("clientIp", ""),
        "internal_testing": bool(e.get("internalTesting")),
        "internal_ranges": e.get("internalRanges", "") or "",
        "internal_access": e.get("internalAccess", "") or "",
        "company": c.get("organization", ""),
        "client_contact": c.get("contact", "") or "",
        "client_email": c.get("email", "") or "",
        "scope": (d.get("scope_check") or {}).get("answers") if isinstance(d.get("scope_check"), dict) else None,
        "signed_by": a.get("typedLegalName", ""),
        "sig": bool(a.get("signaturePresent")),
        "photo": bool(a.get("identityPhotoPresent")),
        "photo_code": (a.get("photo_code") or "").strip().upper(),
        "quote": d.get("quote") if isinstance(d.get("quote"), dict) else None,
        "quote_approved": d.get("quote_approved"),
        "quote_approved_by": d.get("quote_approved_by") or "",
        "quote_approved_date": d.get("quote_approved_date") or "",
        "quote_signature_captured": d.get("quote_signature_captured"),
        "quote_hash": d.get("quote_hash") or "",
        "internal_requested": e.get("internalTesting") is True,
        "internal_cidr": internal_scan.norm_cidrs(e.get("internalCidr") or e.get("internalRanges") or "")
                         if e.get("internalTesting") is True else "",
        "internal_raw": str(e.get("internalRanges") or ""),
        "internal_access": str(e.get("internalAccess") or ""),
        "internal_safety_ack": e.get("internalSafetyAck") is True,
        "internal_notes": "; ".join(x for x in [
            "always-on PC available" if e.get("internalPcAvailable") else "",
            "prefers drop box" if e.get("internalPreferDropBox") else "",
            str(e.get("internalNotes") or "").strip()] if x),
    }


def validate_internal(info):
    """Inside-out gate. Returns (status, detail):
       ('not_requested', '')         neither auth nor quote asked for internal testing
       ('ok', cidr)                  signed auth AND signed quote both request it with the SAME valid CIDR
       ('refused', reason)           requested somewhere but not consistently/validly — internal is skipped.
    Never affects the outside-in gate. Only call AFTER validate_authorization() passed
    (so the quote hash/signature already covers the quote's internal fields)."""
    q = info.get("quote") if isinstance(info.get("quote"), dict) else {}
    q_req = bool(q.get("internal"))
    a_req = info.get("internal_requested") is True
    if not q_req and not a_req:
        return "not_requested", ""
    if a_req and not q_req:
        return "refused", "the client asked for internal testing but the signed quote doesn't include it — re-issue the quote with the internal add-on"
    if q_req and not a_req:
        return "refused", "the quote includes internal testing but the signed authorization didn't check \"Include internal (inside-out) network assessment\""
    qc = internal_scan.norm_cidrs(q.get("internalCidr"))
    ac = info.get("internal_cidr") or ""
    if not qc:
        return "refused", "the quote's internal LAN range is missing/invalid"
    if not ac:
        return "refused", "the authorization's internal LAN range %s is missing/invalid (private range, /22 or smaller)" % _shown(info.get("internal_raw"))
    if qc != ac:
        return "refused", "authorized LAN range `%s` doesn't match quote `%s`" % (ac, qc)
    if info.get("internal_safety_ack") is not True:
        return "refused", "the client didn't tick the internal-testing safety acknowledgement on the authorization"
    return "ok", ac


def run_internal(info, dry_run=False):
    """Gate + Tailscale readiness + scan. Returns dict for the report/summary. Never raises."""
    status, detail = validate_internal(info)
    if status == "not_requested":
        return {"status": "not_requested"}
    if status == "refused":
        return {"status": "refused", "reason": detail}
    cidr = detail
    try:
        ready, why, peer = internal_scan.tailscale_readiness(cidr)
    except Exception as ex:
        ready, why, peer = False, "Tailscale check failed (%s)" % type(ex).__name__, None
    if not ready:
        return {"status": "not_ready", "cidr": cidr, "reason": why}
    if dry_run:
        return {"status": "dry_run", "cidr": cidr, "peer": peer}
    try:
        res = internal_scan.scan_internal(cidr, via="socks")
    except Exception as ex:
        return {"status": "error", "cidr": cidr, "reason": "internal scan error (%s)" % type(ex).__name__}
    return {"status": "done", "cidr": cidr, "peer": peer, "result": res,
            "findings": internal_scan.findings(res)}


INTERNAL_CLIENT_TODO = ("Client still needs to: install Tailscale on an always-on PC at the site, join COTHE's "
                        "tailnet with the invite from their COTHE contact, and turn on subnet routing for their "
                        "LAN (steps: https://holydog413.github.io/cothe-llc/setup/#tailscale). Then Rene approves "
                        "the route in the COTHE Tailscale admin console.")


def internal_discord_line(it):
    s = it.get("status")
    if s == "not_requested":
        return "Inside-out: not requested."
    if s == "refused":
        return "⛔ Inside-out NOT run — %s." % it.get("reason")
    if s == "not_ready":
        return ("⛔ Inside-out NOT run for LAN `%s` — %s.\n%s\nOnce it's ready, reply `run internal` to the "
                "authorization message (one internal run per authorization)."
                % (it.get("cidr"), it.get("reason"), INTERNAL_CLIENT_TODO))
    if s == "error":
        return "⚠️ Inside-out failed for LAN `%s` — %s." % (it.get("cidr"), it.get("reason"))
    if s == "dry_run":
        return "Inside-out (dry run): LAN `%s` ready via %s." % (it.get("cidr"), (it.get("peer") or {}).get("host"))
    r = it["result"]
    hi = sum(1 for f in it["findings"] if f[0] in ("high", "medium"))
    return ("🏠 Inside-out: LAN `%s` — %d live host(s), %d open service(s), %d high/medium finding(s)."
            % (it["cidr"], len(r["hosts"]), sum(len(v) for v in r["hosts"].values()), hi))


def removal_checklist_lines(cleanup_at=""):
    done = ("- [x] COTHE removed the client device and its subnet route from COTHE's tailnet — %s" % cleanup_at
            if cleanup_at else
            "- [ ] COTHE removed the client device and its subnet route from COTHE's tailnet "
            "(operator: reply `cleanup` to the authorization, or remove in Tailscale admin → Machines) — date/time: ________")
    return ["### Removal checklist", "",
            done,
            "- [ ] COTHE deleted this client's access rule (grant) from the tailnet policy",
            "- [ ] Client uninstalled Tailscale on Windows: right-click the Tailscale icon by the clock → **Log out**, "
            "then Start → Settings → Apps → Installed apps → **Tailscale** → **Uninstall** "
            "(drop box: unplug it and mail it back in the prepaid box)",
            "",
            "**COTHE keeps no access afterward.** Once the device is removed, COTHE has no connection to your "
            "network, no saved logins, and nothing installed on your devices.", ""]


def internal_report_lines(it):
    L = ["## 2. Inside-out findings (LAN view via Tailscale)", ""]
    s = (it or {}).get("status", "not_requested")
    if s == "not_requested":
        L += ["Not requested — this engagement covered the outside-in (internet) view only.", ""]
        return L
    if s in ("refused", "not_ready", "error"):
        L += ["**Not performed.** %s" % (it.get("reason") or "")]
        if s == "not_ready":
            L += ["", "Client Tailscale not ready. " + INTERNAL_CLIENT_TODO]
        L.append("")
        return L
    if s == "dry_run":
        L += ["Dry run — Tailscale ready for `%s`; no LAN scan performed." % it.get("cidr"), ""]
        return L
    r = it["result"]
    L += ["- **Authorized LAN range (only range scanned):** `%s`" % it["cidr"],
          "- **Path:** COTHE scan box → Tailscale → client subnet router `%s`" % (it.get("peer") or {}).get("host", "?"),
          "- **Addresses checked:** %d · **live hosts:** %d · **time:** %ss" % (r["targets"], len(r["hosts"]), r["seconds"]),
          "- **Method:** TCP connect to common ports + short banner read. No logins, no exploits, nothing written to client devices.",
          ""]
    if r["hosts"]:
        L += ["| Host | Open services |", "|---|---|"]
        for h, ps in r["hosts"].items():
            L.append("| `%s` | %s |" % (h, ", ".join("%d/%s" % (p["port"], p["service"] or "?") for p in ps) or "— (responds, no common ports open)"))
        L.append("")
    else:
        L += ["No live hosts answered on common ports.", ""]
    L += ["### Risk notes", ""]
    if it["findings"]:
        icon = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "ℹ️"}
        for sev, h, p, note in it["findings"]:
            L.append("- %s **%s** `%s:%d` — %s" % (icon[sev], sev.upper(), h, p, note))
    else:
        L.append("- No obvious risky services found on the LAN among common ports.")
    L.append("")
    L += removal_checklist_lines(it.get("cleanup_at", ""))
    return L


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
    qr = validate_quote(info)
    if qr:
        missing.append("quote not approved/signed (" + ", ".join(qr) + ")")
    elif "client_email" in info:  # answers.json mode: enforce auth/scope-vs-quote consistency
        mr = validate_quote_match(info)
        if mr:
            missing.append("authorization doesn't match quote (" + "; ".join(mr) + ")")
        sr = validate_scope(info)
        if sr:
            missing.append("quote under-covers scope (" + "; ".join(sr) + ")")
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
    ap.add_argument("--internal", action="store_true",
                    help="Internal (inside-out) run from a machine inside the client network")
    ap.add_argument("--ranges", default="", help="Internal ranges (manual mode with --internal)")
    ap.add_argument("--dry-run", action="store_true", help="Scan + build report, print, do not post or mark seen")
    args = ap.parse_args()

    if args.answers:
        info = resolve_photo(extract_from_answers(args.answers))
    else:
        if not args.ip and not args.internal:
            ap.error("provide --answers or --ip")
        info = {"ip": args.ip, "company": args.company, "signed_by": args.signed_by,
                "sig": args.i_have_verified_authorization,
                "photo": args.i_have_verified_authorization}
        if args.internal:
            info.update({"internal_testing": True, "internal_ranges": args.ranges})

    # When using answers.json, always enforce the full authorization gate.
    # In manual mode, require either answers or the explicit attestation.
    if args.answers:
        ok, missing = validate_authorization(info)
        if args.internal and not is_public_ip(info.get("ip", "")):
            # Public IP isn't the target of an internal run; don't block on it.
            missing = [m for m in missing if "public client IP" not in m]
            ok = not missing
    else:
        if args.i_have_verified_authorization and args.internal:
            ok, missing = True, []
        elif args.i_have_verified_authorization:
            ok = is_public_ip(info["ip"])
            missing = [] if ok else ["a valid public client IP is missing/invalid"]
        else:
            ok, missing = False, ["manual mode requires --answers or --i-have-verified-authorization"]

    ip = info["ip"]
    if not ok:
        reason = "; ".join(missing)
        qr = validate_quote(info) if args.answers else []
        mr = validate_quote_match(info) if (args.answers and not qr) else []
        sr = validate_scope(info) if (args.answers and not qr) else []
        if mr or sr:
            parts = []
            if mr:
                parts.append("⛔ **Won't run — authorization doesn't match quote** for IP `%s`:\n%s"
                             % (ip or "?", "\n".join("• " + x for x in mr)))
            if sr:
                parts.append("⛔ **Won't run — quote needs update (under-covers scope)**%s:\n%s"
                             % ("" if mr else " for IP `%s`" % (ip or "?"), "\n".join("• " + x for x in sr)))
            other = [x for x in missing if not x.startswith(("authorization doesn't match quote", "quote under-covers scope"))]
            if other:
                parts.append("Also missing: " + "; ".join(other) + ".")
            msg = "\n".join(parts) + "\nNo scan was performed."
        elif qr:
            msg = ("⛔ **Won't run — quote not approved/signed** for IP `%s`: %s. "
                   "No scan was performed." % (ip or "?", reason))
        else:
            msg = ("⛔ **Won't run** for IP `%s` — authorization incomplete: %s. "
                   "No scan was performed." % (ip or "?", reason))
        print(msg, file=sys.stderr)
        if not args.dry_run:
            post_webhook(content=msg)
        sys.exit(2)

    nets = []
    if args.internal:
        if not info.get("internal_testing"):
            msg = ("⛔ **Won't run internal test** — the client did not authorize internal "
                   "(inside-out) testing on this authorization. No scan was performed.")
            print(msg, file=sys.stderr)
            if not args.dry_run:
                post_webhook(content=msg)
            sys.exit(2)
        if args.answers:
            ist, idet = validate_internal(info)
            if ist != "ok":
                msg = ("⛔ **Won't run internal test** — %s. No scan was performed."
                       % (idet or "internal testing is not on both the signed authorization and the signed quote"))
                print(msg, file=sys.stderr)
                if not args.dry_run:
                    post_webhook(content=msg)
                sys.exit(2)
            info["internal_ranges"] = idet  # scan exactly the CIDR both signed documents agree on
        nets, errs = parse_internal_ranges(info.get("internal_ranges"))
        if errs:
            msg = ("⛔ **Won't run internal test** — authorized ranges invalid: %s. "
                   "No scan was performed." % "; ".join(errs))
            print(msg, file=sys.stderr)
            if not args.dry_run:
                post_webhook(content=msg)
            sys.exit(2)
        if not host_inside(nets):
            msg = ("⛔ **Won't run internal test** — this scanner is not connected inside the "
                   "authorized range(s) `%s`. Run it on-site / from the client scan device. "
                   "No scan was performed." % ", ".join(map(str, nets)))
            print(msg, file=sys.stderr)
            if not args.dry_run:
                post_webhook(content=msg)
            sys.exit(5)
        ip = ", ".join(map(str, nets))

    # Payment gate.
    payment = payments.find_payment(args.auth_id)
    if not payment:
        print(NO_PAYMENT_MSG, file=sys.stderr)
        if not args.dry_run:
            post_webhook(content=NO_PAYMENT_MSG)
        sys.exit(4)

    # Cap: one run per authorization message id.
    seen = load_seen()
    key = args.auth_id or ("ip:" + ip)
    if args.internal:
        key += ":internal"
    if not args.dry_run and key in seen:
        msg = ("⛔ **Already run** for authorization `%s` (IP `%s`) at %s by %s. "
               "One run per authorization — refusing to re-scan." %
               (key, ip, seen[key].get("at"), seen[key].get("operator")))
        print(msg, file=sys.stderr)
        post_webhook(content=msg)
        sys.exit(3)

    if args.internal:
        start_msg = ("▶️ **Started by %s** — running a non-destructive INTERNAL (inside-out) "
                     "assessment of `%s`%s. Authorized by %s. Paid: %s." %
                     (args.operator, ip, (" for **%s**" % info["company"]) if info.get("company") else "",
                      info.get("signed_by") or "—", payments.describe(payment)))
        print(start_msg, file=sys.stderr)
        if not args.dry_run:
            post_webhook(content=start_msg)
        scan = run_internal_scan(nets)
        report = build_internal_report(scan, args.operator, info.get("company"), info.get("signed_by"),
                                       args.auth_id, payment, info.get("internal_access", ""))
        md_path = os.path.join(REPORTS, "report-%s-%s.md" % (scan["label"], scan["stamp"]))
        open(md_path, "w").write(report)
        summary = ("✅ **Internal assessment complete** — `%s`, authorized by %s, run by %s. "
                   "%d device(s), %d open common port(s). Full report attached." %
                   (ip, info.get("signed_by") or "—", args.operator, len(scan["hosts"]), len(scan["ports"])))
        if args.dry_run:
            print("\n===== REPORT (dry-run) =====\n" + report + "\n===== SUMMARY =====\n" + summary)
        else:
            post_webhook(content=summary, file_path=md_path)
            seen[key] = {"at": datetime.datetime.now().isoformat(timespec="seconds"),
                         "operator": args.operator, "ip": ip, "company": info.get("company"),
                         "report": md_path, "type": "internal"}
            save_seen(seen)
        print("done", file=sys.stderr)
        return

    # Announce
    start_msg = ("▶️ **Started by %s** — running a non-destructive external assessment "
                 "of Client IP `%s`%s. Authorized by %s." %
                 (args.operator, ip,
                  (" for **%s**" % info["company"]) if info.get("company") else "",
                  info.get("signed_by") or "—"))
    start_msg += " Run started by %s. Paid: %s." % (args.operator, payments.describe(payment))
    print(start_msg, file=sys.stderr)
    if not args.dry_run:
        post_webhook(content=start_msg)

    scan = run_scan(ip)
    internal = run_internal(info, dry_run=args.dry_run) if args.answers else {"status": "not_requested"}
    report = build_report(scan, args.operator, info.get("company"),
                          info.get("signed_by"), args.auth_id, payment, internal)
    md_path = os.path.join(REPORTS, "report-%s-%s.md" % (ip.replace(":", "_"), scan["stamp"]))
    os.makedirs(REPORTS, exist_ok=True)
    open(md_path, "w").write(report)
    print("[report written] " + md_path, file=sys.stderr)

    nopen = len(scan["ports"])
    summary = ("✅ **Assessment complete** — IP `%s`, authorized by %s, run by %s. "
               "%d open common port(s) found. Full report attached.\n%s" %
               (ip, info.get("signed_by") or "—", args.operator, nopen, internal_discord_line(internal)))
    if args.dry_run:
        print("\n===== REPORT (dry-run) =====\n")
        print(report)
        print("\n===== SUMMARY =====\n" + summary)
    else:
        post_webhook(content=summary, file_path=md_path)
        seen[key] = {"at": datetime.datetime.now().isoformat(timespec="seconds"),
                     "operator": args.operator, "ip": ip,
                     "company": info.get("company"), "report": md_path,
                     "internal": internal.get("status"), "internal_cidr": internal.get("cidr", "")}
        save_seen(seen)
    print("done", file=sys.stderr)


if __name__ == "__main__":
    main()
