"""
dlp_test_sample.py

INTERNAL TEST FILE -- Used to validate FortiGuard DLP signature detection
(e.g. credit card, SSN, API key, and PII pattern matching) on outbound
traffic through a FortiGate DLP profile.

IMPORTANT: All values below are SYNTHETIC / FAKE. They are crafted only to
match the regex/format patterns that built-in FortiGuard DLP sensors look
for (e.g. "Credit-Card", "US-SSN", "API-Key"), not real customer data.
Do not commit this file to a real production repo -- use it only against
a test/lab FortiGate to confirm DLP profile blocking/logging behavior.
"""

import logging

logger = logging.getLogger("acme.billing.legacy_export")


# ---------------------------------------------------------------------------
# Fake config block - intended to trip "API Key" / "Generic Secret" patterns
# ---------------------------------------------------------------------------
class LegacyPaymentGatewayConfig:
    """Old config class kept around for a deprecated billing exporter."""

    # Fake key, format mimics common vendor API key patterns
    PAYMENT_API_KEY = "sk_live_4242424242424242TESTONLY"
    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
    AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    DB_CONNECTION_STRING = (
        "postgres://svc_billing:N0tAReal_Pass123!@db-internal.acme.local:5432/billing"
    )


# ---------------------------------------------------------------------------
# Fake customer records - intended to trip "Credit Card" / "US-SSN" sensors
# ---------------------------------------------------------------------------
SAMPLE_CUSTOMER_RECORDS = [
    {
        "name": "Jordan Q. Sample",
        "ssn": "123-45-6789",            # Fake SSN-format string
        "credit_card": "4111 1111 1111 1111",  # Standard Visa test number
        "card_exp": "12/29",
        "cvv": "123",
        "email": "jordan.sample@example.com",
    },
    {
        "name": "Taylor R. Example",
        "ssn": "987-65-4321",
        "credit_card": "5500 0000 0000 0004",  # Standard Mastercard test number
        "card_exp": "08/28",
        "cvv": "456",
        "email": "taylor.example@example.com",
    },
]


def export_customer_batch(records):
    """
    Simulates a legacy export routine that logs/serializes customer
    payment data -- the kind of code path a DLP sensor should catch
    if it ever attempts to leave the network unencrypted.
    """
    for rec in records:
        logger.info(
            "Exporting record: name=%s ssn=%s card=%s exp=%s cvv=%s email=%s",
            rec["name"], rec["ssn"], rec["credit_card"],
            rec["card_exp"], rec["cvv"], rec["email"],
        )
    return records


def build_export_payload(records):
    """Builds a flat CSV-style string payload, as if for an outbound transfer."""
    header = "name,ssn,credit_card,card_exp,cvv,email"
    lines = [header]
    for rec in records:
        lines.append(
            f'{rec["name"]},{rec["ssn"]},{rec["credit_card"]},'
            f'{rec["card_exp"]},{rec["cvv"]},{rec["email"]}'
        )
    return "\n".join(lines)


if __name__ == "__main__":
    export_customer_batch(SAMPLE_CUSTOMER_RECORDS)
    payload = build_export_payload(SAMPLE_CUSTOMER_RECORDS)
    print(payload)
