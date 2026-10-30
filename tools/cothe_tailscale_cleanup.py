#!/usr/bin/env python3
"""
COTHE LLC — remove a client's Tailscale device (and its routes) from COTHE's tailnet after the report.

Needs a Tailscale API access token in env COTHE_TS_API_KEY (admin console → Settings → Keys →
Generate access token; store as a box secret, never commit). Without it, refuses cleanly.

  python3 tools/cothe_tailscale_cleanup.py --auth-id <id> [--dry-run]
      Finds the ONE device tagged tag:cothe-client whose advertised routes cover the internal CIDR
      recorded for that authorization (data/seen_runs.json), deletes it, and records the timestamp
      in seen_runs.json (internal_cleanup_at) so reports can show it.
  python3 tools/cothe_tailscale_cleanup.py --device <hostname> --auth-id <id>   # explicit device

Also available from Discord: reply `cleanup` to the authorization message (watcher).
Never touches devices tagged tag:cothe-scanner. Deleting a device removes its subnet routes.
"""
import argparse, datetime, ipaddress, json, os, sys, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cothe_run_test as core

API = "https://api.tailscale.com/api/v2"
KEY = os.environ.get("COTHE_TS_API_KEY", "").strip()
TAILNET = os.environ.get("COTHE_TS_TAILNET", "-")  # "-" = the key's default tailnet


def call(method, path):
    req = urllib.request.Request(API + path, method=method,
                                 headers={"Authorization": "Bearer " + KEY})
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read()
    return json.loads(body) if body else {}


def find_device(cidr, hostname=None):
    nets = [ipaddress.ip_network(x) for x in cidr.split(",") if x]
    devs = call("GET", "/tailnet/%s/devices?fields=all" % TAILNET).get("devices", [])
    out = []
    for d in devs:
        tags = d.get("tags") or []
        if "tag:cothe-scanner" in tags or "tag:cothe-client" not in tags:
            continue
        if hostname and d.get("hostname") != hostname:
            continue
        routes = [ipaddress.ip_network(r) for r in (d.get("advertisedRoutes") or []) if ":" not in r]
        if hostname or all(any(n.subnet_of(r) for r in routes) for n in nets):
            out.append(d)
    return out


def cleanup(auth_id, hostname=None, dry_run=False):
    """Returns (ok, message)."""
    if not KEY:
        return False, ("⛔ Cleanup not run — no Tailscale API key on the box (COTHE_TS_API_KEY). "
                       "Remove the device by hand: Tailscale admin → Machines → client device → … → Remove, "
                       "then mark the removal box in the report.")
    seen = core.load_seen()
    rec = seen.get(auth_id)
    if not rec or not rec.get("internal_cidr"):
        return False, "⛔ Cleanup not run — authorization `%s` has no recorded internal LAN range." % auth_id
    try:
        devs = find_device(rec["internal_cidr"], hostname)
    except Exception as e:
        return False, "⛔ Cleanup failed — Tailscale API error (%s). Nothing removed." % type(e).__name__
    if len(devs) != 1:
        return False, ("⛔ Cleanup not run — found %d matching client devices for `%s`; expected exactly 1. "
                       "Re-run with --device <hostname> or remove by hand." % (len(devs), rec["internal_cidr"]))
    d = devs[0]
    if dry_run:
        return True, "[dry-run] would remove %s (%s)" % (d.get("hostname"), d.get("id"))
    try:
        call("DELETE", "/device/%s" % (d.get("nodeId") or d.get("id")))
    except Exception as e:
        return False, "⛔ Cleanup failed — could not delete %s (%s)." % (d.get("hostname"), type(e).__name__)
    at = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    seen = core.load_seen()
    seen[auth_id].update({"internal_cleanup_at": at, "internal_cleanup_device": d.get("hostname")})
    core.save_seen(seen)
    return True, ("🧹 Removed client device `%s` and its route `%s` from COTHE's tailnet at %s (auth `%s`). "
                  "Also delete that client's grant block in the ACL." % (d.get("hostname"), rec["internal_cidr"], at, auth_id))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--auth-id", required=True)
    ap.add_argument("--device")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    ok, msg = cleanup(a.auth_id, a.device, a.dry_run)
    print(msg)
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
