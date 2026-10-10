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
