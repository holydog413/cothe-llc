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
