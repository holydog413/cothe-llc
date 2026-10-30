# COTHE LLC

Veteran-owned network security assessments for homes and small businesses.

Live site: https://holydog413.github.io/cothe-llc/

Authorization form: https://holydog413.github.io/cothe-llc/authorize/

## Payments (run-test gate)

`run test` only runs when a payment is recorded for the intake authorization.
Cash: a team member replies `paid cash` (optional amount, e.g. `paid cash 249`) to the
COTHE Intake authorization in #intake; the watcher stores it in `data/payments.json`
(gitignored) and posts a confirmation. Payment sources live in `tools/cothe_payments.py`.

### Enabling Stripe (later)
1. Create a Stripe Payment Link per quote, passing the intake authorization message id as
   `client_reference_id` (or `metadata.auth_id`).
2. Either add a webhook endpoint for `checkout.session.completed` that writes
   `{"method": "stripe", "amount", "recorded_by": "Stripe", "at", "auth_id"}` into
   `data/payments.json`, or implement polling in `StripeProvider.lookup()` (Checkout Sessions API).
3. Set `STRIPE_SECRET_KEY` (box secret, never committed). Without it Stripe is skipped quietly.

## Internal ("inside-out") testing

Clients opt in on the authorization form ("Also test my internal network"), listing the
private range(s) in scope (RFC1918, each /22 or smaller) and the access method (on-site
visit or a plug-in scan device). These are saved as `engagement.internalTesting`,
`internalRanges`, `internalAccess` and shown in the Discord intake post.

Run it from a machine connected **inside** the client network:

    python3 tools/cothe_run_test.py --internal --answers answers.json --operator "Name" --auth-id <id>

Same signature/photo/quote/payment gates as the external run. It refuses if the client
didn't opt in, if ranges are not private or too large, or if the scanner has no address
inside an authorized range. Non-destructive only (host discovery + TCP connect scan of
common ports, light version detection, safe scripts). One internal run per authorization
(seen key `<auth-id>:internal`), separate from the external run. The Discord `run test`
watcher on the box still runs external scans only.

## Outside-in + inside-out assessments

- **Outside-in** (always): nmap TCP-connect scan of the client's public IP from the box.
- **Inside-out** (optional add-on, Home $149 / Business $395): LAN scan through COTHE's Tailscale
  network. Runs only when the signed authorization **and** the signed quote both include
  "Internal (inside-out) network assessment" with the **same** private CIDR (/22 or smaller), and
  exactly one online tailnet device has an approved subnet route covering it. Otherwise the internal
  part is refused with a Discord note and outside-in still runs. Later, reply `run internal` to the
  authorization to run just the internal part (once).
- Client steps: `setup/#tailscale`. Drop-box option documented at `setup/#dropbox`.

### One-time Tailscale setup (Rene)
1. Create a Tailscale account for COTHE LLC (https://login.tailscale.com/start).
2. Admin console → Settings → Keys → **Generate auth key** (reusable, tagged `tag:cothe-scanner` if
   you add that tag in Access controls). Save it in box secrets as `COTHE_TS_AUTHKEY`.
3. Join the box once: `COTHE_TS_AUTHKEY=... tools/cothe_tailscale_box.sh up`
   (separate daemon: `/opt/cothe-tailscale`, state `~/.cothe-tailscale`, SOCKS `127.0.0.1:1056`).
4. Per client: send an invite (Admin → Users → Invite) or a one-off auth key; after they run
   `tailscale up --advertise-routes=<their CIDR>`, approve the route on their machine
   (Machines → … → Edit route settings). Remove the device + route when the report is delivered.
5. Fill the invite placeholder on `setup/index.html` (search `ask your COTHE contact for the invite`)
   if you want a standing invite link.

Self-test (no client traffic): `python3 tools/cothe_watch_run_test.py --self-test`

### Tailscale access rules (ACL) — paste once
1. Open `tools/tailscale-acl.hujson`, replace `COTHE_ADMIN_EMAIL` with the COTHE admin login.
2. Tailscale admin console → **Access controls** → JSON editor → replace contents → **Save**
   (the `tests` block must pass or Tailscale refuses the save).
3. The box joins with `tag:cothe-scanner` (generate its auth key with that tag).
4. **Per client:** add one grant block `{ "src": ["tag:cothe-scanner"], "dst": ["<their CIDR>"], "ip": ["tcp:*"] }`
   matching the CIDR on their signed authorization; delete it when the report is delivered.
   Client devices get no grants, so they can't reach the scanner, other clients, or anything else.

### One-time client auth keys
Admin console → Settings → **Keys** → Generate auth key: **not** reusable, **Pre-approved** on,
**Tags:** `tag:cothe-client`, **Expiration: 1 day**. Send it only to that client (it replaces
`YOUR_TAILSCALE_AUTH_KEY` in their setup command). Then approve their subnet route by hand.

### Cleanup after the report
Reply `cleanup` to the authorization in #intake (or `python3 tools/cothe_tailscale_cleanup.py --auth-id <id>`).
Needs a Tailscale API access token as box secret `COTHE_TS_API_KEY`; without it the tool refuses and
tells you to remove the device by hand (Machines → … → Remove). Every inside-out report includes a
Removal checklist.
