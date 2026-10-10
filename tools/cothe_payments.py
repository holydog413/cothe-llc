#!/usr/bin/env python3
"""COTHE LLC payment records + payment-method abstraction.

A run-test is only allowed once a payment exists for the intake authorization
message id. Payment sources ("providers") are checked in order:

  * CashProvider   — records written by the watcher when a team member replies
                     `paid cash [amount]` to the authorization (data/payments.json,
                     gitignored).
  * StripeProvider — placeholder for Stripe (Payment Link + webhook or polling).
                     Skipped quietly when STRIPE_SECRET_KEY is unset.

Each provider returns a payment dict or None:
  {"method", "amount", "recorded_by", "recorded_by_username", "at", "auth_id", ...}
"""
import datetime, json, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(os.path.dirname(HERE), "data")
PAYMENTS = os.environ.get("COTHE_PAYMENTS_FILE") or os.path.join(DATA, "payments.json")
PAID_CASH_RE = re.compile(r"^\s*paid\s+cash(?:\s+\$?\s*(\d+(?:\.\d{1,2})?))?\s*$", re.IGNORECASE)


def parse_paid_cash(text):
    """Returns (True, amount_or_None) for a `paid cash [amount]` message, else (False, None)."""
    m = PAID_CASH_RE.match(text or "")
    if not m:
        return False, None
    return True, (float(m.group(1)) if m.group(1) else None)


def load_payments(path=None):
    path = path or PAYMENTS
    try:
        d = json.load(open(path))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save_payments(d, path=None):
    path = path or PAYMENTS
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    json.dump(d, open(tmp, "w"), indent=2)
    os.replace(tmp, path)


def record_cash(auth_id, amount, recorded_by, username="", source_msg_id="", company="", path=None):
    """Record a cash payment. Returns the record, or None if this source message was already processed."""
    d = load_payments(path)
    done = d.setdefault("_processed_msgs", [])
    if source_msg_id and source_msg_id in done:
        return None
    rec = {"method": "cash", "amount": amount, "recorded_by": recorded_by,
           "recorded_by_username": username, "auth_id": str(auth_id), "company": company,
           "source_msg_id": source_msg_id,
           "at": datetime.datetime.now().astimezone().isoformat(timespec="seconds")}
    d[str(auth_id)] = rec
    if source_msg_id:
        done.append(source_msg_id)
    save_payments(d, path)
    return rec


def is_processed(source_msg_id, path=None):
    return source_msg_id in load_payments(path).get("_processed_msgs", [])


def mark_nopay_notified(run_msg_id, path=None):
    """True the first time a given `run test` msg is refused for no payment (post once)."""
    d = load_payments(path)
    lst = d.setdefault("_nopay_notified", [])
    if run_msg_id in lst:
        return False
    lst.append(run_msg_id)
    save_payments(d, path)
    return True


def fmt_amount(amount):
    if amount is None:
        return ""
    return " $%s" % (("%d" % amount) if float(amount).is_integer() else ("%.2f" % amount))


def describe(p):
    """'cash $249, recorded by Martin'"""
    if not p:
        return ""
    s = "%s%s" % (p.get("method", "?"), fmt_amount(p.get("amount")))
    if p.get("recorded_by"):
        s += ", recorded by %s" % p["recorded_by"]
    return s


class CashProvider:
    name = "cash"

    def lookup(self, auth_id):
        rec = load_payments().get(str(auth_id))
        return rec if isinstance(rec, dict) and rec.get("method") == "cash" else None


class StripeProvider:
    """Future: Stripe Payment Link with client_reference_id / metadata.auth_id = intake message id.
    Either a webhook (checkout.session.completed) writes a record with method=stripe into
    payments.json, or lookup() polls Checkout Sessions with STRIPE_SECRET_KEY. Not implemented yet;
    quietly returns None when no key is configured."""
    name = "stripe"

    def lookup(self, auth_id):
        if not os.environ.get("STRIPE_SECRET_KEY", "").strip():
            return None
        rec = load_payments().get(str(auth_id))  # webhook-written records
        if isinstance(rec, dict) and rec.get("method") == "stripe":
            return rec
        return None  # TODO: poll Stripe Checkout Sessions by metadata.auth_id


PROVIDERS = [CashProvider(), StripeProvider()]


def find_payment(auth_id):
    if not auth_id:
        return None
    for p in PROVIDERS:
        try:
            rec = p.lookup(auth_id)
        except Exception:
            rec = None
        if rec:
            return rec
    return None
