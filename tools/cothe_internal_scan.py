#!/usr/bin/env python3
"""
COTHE LLC — inside-out (LAN) assessment over Tailscale.

The box runs its OWN tailscaled for COTHE (separate from any other tailscaled on the box):
  userspace networking, SOCKS5 on 127.0.0.1:1056, state in ~/.cothe-tailscale/.
The client's always-on PC runs Tailscale as a *subnet router* advertising their LAN CIDR,
and Rene approves that route in COTHE's Tailscale admin console.

This module:
  * norm_cidrs()            — validates/normalizes the authorized LAN range(s): private IPv4 only,
                              each /22 or smaller (same rules as the quote builder + authorize form).
  * tailscale_readiness()   — checks the COTHE tailnet: box logged in, and exactly one ONLINE peer
                              whose approved subnet route covers every authorized CIDR.
  * scan_internal()         — non-destructive TCP-connect sweep of ONLY the authorized CIDR(s):
                              host discovery on a few ports, then common ports on live hosts,
                              light banner read. No exploits, no logins, no writes, no UDP floods.
  * findings()              — "obvious risk" notes (telnet, SMB, RDP, VNC, DBs, MQTT, cameras ...).

CLI (self-test / manual):
  python3 tools/cothe_internal_scan.py --status              # COTHE tailnet readiness (no scan)
  python3 tools/cothe_internal_scan.py --self-test           # scans 127.0.0.1 only, direct (labeled self-test)
"""
import argparse, concurrent.futures as cf, ipaddress, json, os, socket, struct, subprocess, sys, time

TS_DIR = os.environ.get("COTHE_TS_DIR", os.path.expanduser("~/.cothe-tailscale"))
TS_BIN = os.environ.get("COTHE_TS_BIN", "/opt/cothe-tailscale/tailscale")
TSD_BIN = os.environ.get("COTHE_TSD_BIN", "/opt/cothe-tailscale/tailscaled")
TS_SOCK = os.path.join(TS_DIR, "tailscaled.sock")
SOCKS = ("127.0.0.1", int(os.environ.get("COTHE_TS_SOCKS_PORT", "1056")))
MAX_HOSTS = 1024  # /22

DISCOVERY_PORTS = [80, 443, 445, 139, 22, 3389, 53, 8080, 9100, 554, 5000, 62078, 135]
COMMON_PORTS = sorted(set(DISCOVERY_PORTS + [
    21, 23, 25, 110, 143, 389, 548, 631, 1433, 1883, 1900, 3306, 5001, 5432, 5900, 5985,
    6379, 8000, 8008, 8443, 8888, 9000, 9200, 27017, 32400, 49152]))
SERVICE = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
           135: "msrpc", 139: "netbios", 143: "imap", 389: "ldap", 443: "https", 445: "smb",
           548: "afp", 554: "rtsp", 631: "ipp", 1433: "mssql", 1883: "mqtt", 1900: "upnp",
           3306: "mysql", 3389: "rdp", 5000: "http-alt/upnp", 5001: "https-alt", 5432: "postgres",
           5900: "vnc", 5985: "winrm", 6379: "redis", 8000: "http-alt", 8008: "http-alt",
           8080: "http-proxy", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
           9100: "printer-raw", 9200: "elasticsearch", 27017: "mongodb", 32400: "plex",
           49152: "upnp", 62078: "apple-sync"}
RISK = {
    23: ("high", "Telnet (cleartext logins) on the LAN — disable it or replace with SSH."),
    21: ("medium", "FTP (cleartext) — prefer SFTP; make sure anonymous login is off."),
    445: ("medium", "Windows file sharing (SMB) — confirm SMBv1 is off and shares need a password."),
    139: ("low", "NetBIOS — legacy Windows sharing; disable if not needed."),
    3389: ("medium", "Remote Desktop — keep it LAN-only, require NLA + strong passwords."),
    5900: ("high", "VNC remote control — often weak/no password; require a password or remove."),
    5985: ("low", "WinRM remote management — fine if intended; restrict to admins."),
    1883: ("medium", "MQTT broker (smart-home/IoT) — often no authentication."),
    554: ("medium", "RTSP camera stream — make sure the camera has a non-default password."),
    9100: ("low", "Raw printer port — anyone on the LAN can print; check printer firmware."),
    1433: ("medium", "SQL Server database reachable on the LAN."),
    3306: ("medium", "MySQL database reachable on the LAN."),
    5432: ("medium", "PostgreSQL database reachable on the LAN."),
    6379: ("high", "Redis — usually no password by default."),
    9200: ("high", "Elasticsearch — usually no password by default."),
    27017: ("high", "MongoDB — check authentication is enabled."),
    1900: ("low", "UPnP — devices can open router ports on their own; consider disabling UPnP on the router."),
    49152: ("low", "UPnP device service — see UPnP note."),
    80: ("info", "Web admin page (HTTP, not encrypted) — make sure the default admin password was changed."),
    8080: ("info", "Web admin/proxy page on 8080 — confirm it's expected and password-protected."),
}


# ---------- scope ----------
def norm_cidrs(v):
    """Return normalized 'a.b.c.d/n,...' or '' if ANY part is invalid (private IPv4, /22../32)."""
    parts = [p for p in str(v or "").replace(";", ",").replace(" ", ",").split(",") if p.strip()]
    out = []
    for p in parts:
        p = p.strip()
        if "/" not in p:
            p += "/32"
        try:
            net = ipaddress.IPv4Network(p, strict=False)
        except ValueError:
            return ""
        if net.prefixlen < 22 or not any(net.subnet_of(ipaddress.IPv4Network(x)) for x in
                                         ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
            return ""
        out.append(str(net))
    return ",".join(out)


def networks(cidrs):
    return [ipaddress.IPv4Network(x) for x in norm_cidrs(cidrs).split(",") if x]


def hosts_in(cidrs):
    hs = []
    for n in networks(cidrs):
        hs.extend(list(n.hosts()) if n.prefixlen < 31 else list(n))
    seen, out = set(), []
    for h in hs:
        if h not in seen:
            seen.add(h); out.append(str(h))
    return out[:MAX_HOSTS]


def in_scope(ip, cidrs):
    a = ipaddress.ip_address(ip)
    return any(a in n for n in networks(cidrs))


# ---------- tailscale ----------
def ts_status():
    if not os.path.exists(TS_BIN):
        return None, "COTHE Tailscale is not installed on the scan box (%s missing)" % TS_BIN
    if os.path.exists(os.path.join(TS_DIR, "state")) and not os.path.exists(TS_SOCK):
        # joined before but daemon not running (e.g. box restarted): start it, stays on COTHE's tailnet only
        try:
            subprocess.run([os.path.join(os.path.dirname(os.path.abspath(__file__)), "cothe_tailscale_box.sh"),
                            "start"], capture_output=True, timeout=30)
        except Exception:
            pass
    try:
        r = subprocess.run([TS_BIN, "--socket=" + TS_SOCK, "status", "--json"],
                           capture_output=True, text=True, timeout=20)
    except Exception as e:
        return None, "could not query COTHE tailscaled (%s)" % type(e).__name__
    if r.returncode != 0 and not r.stdout.strip():
        return None, ("COTHE Tailscale on the scan box is not running/joined yet — Rene runs "
                      "tools/cothe_tailscale_box.sh up once with the COTHE auth key")
    try:
        return json.loads(r.stdout), ""
    except Exception:
        return None, "unreadable tailscale status"


def tailscale_readiness(cidrs):
    """(ok, reason, peer_info). ok only if box is logged in and exactly one online peer
    has an APPROVED route (PrimaryRoutes) covering every authorized CIDR."""
    nets = networks(cidrs)
    if not nets:
        return False, "no valid authorized LAN CIDR", None
    st, err = ts_status()
    if st is None:
        return False, err, None
    if st.get("BackendState") != "Running":
        return False, ("the COTHE scan box is not joined to the COTHE tailnet yet (state: %s) — "
                       "Rene must log the box in once" % st.get("BackendState")), None
    cand, partial = [], []
    for p in (st.get("Peer") or {}).values():
        routes = []
        for r in (p.get("PrimaryRoutes") or []):
            try:
                rn = ipaddress.ip_network(r)
            except ValueError:
                continue
            if rn.version == 4 and rn.prefixlen > 0:
                routes.append(rn)
        covers = all(any(n.subnet_of(rn) for rn in routes) for n in nets)
        name = p.get("HostName") or p.get("DNSName") or "?"
        if covers:
            (cand if p.get("Online") else partial).append({"host": name, "online": bool(p.get("Online")),
                                                           "routes": [str(x) for x in routes]})
    if len(cand) == 1:
        return True, "", cand[0]
    if len(cand) > 1:
        return False, ("more than one online Tailscale device advertises %s (%s) — ambiguous, refusing. "
                       "Disable the other client's route first"
                       % (",".join(map(str, nets)), ", ".join(c["host"] for c in cand))), None
    if partial:
        return False, ("the client's Tailscale device (%s) is OFFLINE — ask the client to turn that PC on "
                       "and make sure Tailscale shows Connected" % partial[0]["host"]), None
    return False, ("no approved subnet route for %s on the COTHE tailnet — the client must finish the "
                   "Tailscale setup (install on an always-on PC, join with the COTHE invite, advertise %s) "
                   "and Rene must approve the route in the Tailscale admin console"
                   % (",".join(map(str, nets)), ",".join(map(str, nets)))), None


# ---------- scanning ----------
def _socks_connect(ip, port, timeout):
    """TCP connect via SOCKS5 (no auth). Returns ('open'|'closed'|'filtered', sock|None)."""
    s = socket.create_connection(SOCKS, timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        s.close(); raise OSError("socks auth")
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(ip) + struct.pack(">H", port))
    rep = s.recv(10)
    if len(rep) < 2:
        s.close(); return "filtered", None
    if rep[1] == 0:
        return "open", s
    s.close()
    return ("closed" if rep[1] == 5 else "filtered"), None


def _direct_connect(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        rc = s.connect_ex((ip, port))
    except socket.timeout:
        s.close(); return "filtered", None
    if rc == 0:
        return "open", s
    s.close()
    return ("closed" if rc == 111 else "filtered"), None


def probe(ip, port, via, timeout=2.0, banner=False):
    try:
        state, s = (_socks_connect if via == "socks" else _direct_connect)(ip, port, timeout)
    except Exception:
        return "filtered", ""
    text = ""
    if s is not None:
        if banner:
            try:
                s.settimeout(1.5)
                if port in (80, 8000, 8008, 8080, 8888, 9000, 5000, 32400):
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\nUser-Agent: COTHE-assessment\r\n\r\n")
                data = s.recv(256)
                text = data.decode("latin-1", "replace")
                if text.startswith("HTTP/"):
                    srv = [l for l in text.splitlines() if l.lower().startswith("server:")]
                    text = text.splitlines()[0] + ((" | " + srv[0]) if srv else "")
                text = " ".join(text.split())[:160]
            except Exception:
                pass
        try:
            s.close()
        except Exception:
            pass
    return state, text


def scan_internal(cidrs, via="socks", workers=48, self_test=False):
    """Scan ONLY hosts inside the authorized CIDR(s). Returns dict for the report."""
    t0 = time.time()
    if self_test:
        targets = ["127.0.0.1"]
        cidrs = "127.0.0.1/32 (self-test)"
    else:
        targets = hosts_in(cidrs)
        for h in targets:  # belt & braces
            assert in_scope(h, cidrs), h
    live = {}
    with cf.ThreadPoolExecutor(workers) as ex:
        futs = {ex.submit(probe, h, p, via, 1.5): (h, p) for h in targets for p in DISCOVERY_PORTS}
        for f in cf.as_completed(futs):
            h, p = futs[f]
            st, _ = f.result()
            if st in ("open", "closed"):
                live.setdefault(h, set())
    hosts = {}
    with cf.ThreadPoolExecutor(workers) as ex:
        futs = {ex.submit(probe, h, p, via, 2.0, True): (h, p) for h in live for p in COMMON_PORTS}
        for f in cf.as_completed(futs):
            h, p = futs[f]
            st, txt = f.result()
            if st == "open":
                hosts.setdefault(h, []).append({"port": p, "service": SERVICE.get(p, ""), "banner": txt})
    for h in live:
        hosts.setdefault(h, [])
    for h in hosts:
        hosts[h].sort(key=lambda x: x["port"])
    return {"cidrs": cidrs, "targets": len(targets), "hosts": dict(sorted(hosts.items(),
            key=lambda kv: ipaddress.ip_address(kv[0]))), "via": via, "self_test": self_test,
            "seconds": round(time.time() - t0, 1)}


def findings(res):
    out = []
    for h, ports in res.get("hosts", {}).items():
        for p in ports:
            if p["port"] in RISK:
                sev, note = RISK[p["port"]]
                out.append((sev, h, p["port"], note))
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return sorted(out, key=lambda x: (order[x[0]], ipaddress.ip_address(x[1]), x[2]))


def main():
    ap = argparse.ArgumentParser(description="COTHE inside-out (LAN via Tailscale) helper")
    ap.add_argument("--status", metavar="CIDR", nargs="?", const="192.168.1.0/24",
                    help="check COTHE tailnet readiness for CIDR (no scan)")
    ap.add_argument("--self-test", action="store_true", help="scan 127.0.0.1 directly (labeled self-test)")
    a = ap.parse_args()
    if a.self_test:
        r = scan_internal("", via="direct", self_test=True)
        print(json.dumps(r, indent=2)); print(findings(r)); return 0
    if a.status:
        print(tailscale_readiness(a.status)); return 0
    ap.print_help(); return 0


if __name__ == "__main__":
    sys.exit(main())
