"""
Behavioral specification: secure webhook handler.

These tests describe what a production-quality webhook handler MUST do.
They serve as a specification — each test corresponds to a correctness or
security requirement that reviewers should check.

Signature format: v1={HMAC-SHA256(secret, "{timestamp_ms}.{body}")}
Timestamp: Unix milliseconds (same as backend Date.now())
Headers:   x-commune-signature, x-commune-timestamp
"""
import hashlib
import hmac
import json
import time

import pytest

from commune.webhooks import verify_signature, WebhookVerificationError


def _sign(payload: bytes, secret: str, timestamp_ms: str) -> str:
    """Replicate the backend signing protocol: v1=HMAC-SHA256(secret, '{ts}.{body}')."""
    digest = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp_ms}.".encode("utf-8") + payload,
        hashlib.sha256,
    ).hexdigest()
    return f"v1={digest}"


class TestWebhookSignatureVerification:
    """Verify that the webhook handler enforces signature validation."""

    def test_valid_signature_is_accepted(self):
        """A correctly signed payload should pass verification."""
        payload = json.dumps({"event": "message.received"}).encode()
        secret = "test_secret_abc123"
        timestamp_ms = str(int(time.time() * 1000))
        sig = _sign(payload, secret, timestamp_ms)
        # Should not raise and should return True
        result = verify_signature(payload=payload, signature=sig, secret=secret, timestamp=timestamp_ms)
        assert result is True

    def test_invalid_signature_raises(self):
        """A payload with a wrong signature must be rejected."""
        payload = json.dumps({"event": "message.received"}).encode()
        timestamp_ms = str(int(time.time() * 1000))
        with pytest.raises(WebhookVerificationError):
            verify_signature(
                payload=payload,
                signature="v1=invalid_sig_hex_that_will_not_match",
                secret="secret",
                timestamp=timestamp_ms,
            )

    def test_raw_bytes_not_parsed_dict(self):
        """Verification must use raw bytes, not a re-serialized dict.

        Parsing and re-serializing a JSON body changes whitespace and key
        ordering, so the HMAC computed over re-serialized bytes will not match
        the signature computed by the backend over the original wire bytes.
        Webhook handlers MUST pass request.body / request.get_data() directly.
        """
        raw = b'{"event":"message.received","data":{"id":1}}'
        re_serialized = json.dumps(json.loads(raw)).encode()
        # Confirm test setup: bytes differ after round-trip
        assert raw != re_serialized, "Test setup: re-serialization should produce different bytes"

        secret = "test_secret"
        timestamp_ms = str(int(time.time() * 1000))
        valid_sig = _sign(raw, secret, timestamp_ms)

        # Signature is valid for the original raw bytes
        assert verify_signature(payload=raw, signature=valid_sig, secret=secret, timestamp=timestamp_ms) is True

        # But NOT for re-serialized bytes — they produce a different HMAC
        with pytest.raises(WebhookVerificationError):
            verify_signature(payload=re_serialized, signature=valid_sig, secret=secret, timestamp=timestamp_ms)

    def test_expired_timestamp_is_rejected(self):
        """Payloads more than 5 minutes old should be rejected (replay protection).

        The default tolerance is 300 seconds. A timestamp 6+ minutes old
        (360 000 ms) must be refused regardless of signature correctness.
        """
        payload = json.dumps({"event": "message.received"}).encode()
        secret = "test_secret"
        # 10 minutes ago in milliseconds
        old_ts_ms = str(int(time.time() * 1000) - 600_000)
        old_sig = _sign(payload, secret, old_ts_ms)
        with pytest.raises(WebhookVerificationError, match="too old"):
            verify_signature(
                payload=payload,
                signature=old_sig,
                secret=secret,
                timestamp=old_ts_ms,
                tolerance_seconds=300,
            )

    def test_empty_secret_is_rejected(self):
        """An empty webhook secret must never accept any payload.

        An empty secret means the signing key has not been configured.
        Accepting requests without a real secret would allow anyone to
        craft a valid-looking webhook delivery.
        """
        payload = b'{"event": "test"}'
        with pytest.raises((WebhookVerificationError, ValueError)):
            verify_signature(
                payload=payload,
                signature="v1=any_sig",
                secret="",
                timestamp=str(int(time.time() * 1000)),
            )

    def test_missing_signature_is_rejected(self):
        """A missing signature header must fail verification.

        An empty signature string represents a missing x-commune-signature
        header. The handler must reject the request before any HMAC work.
        """
        payload = b'{"event": "test"}'
        with pytest.raises(WebhookVerificationError, match="Missing signature"):
            verify_signature(
                payload=payload,
                signature="",
                secret="secret",
                timestamp=str(int(time.time() * 1000)),
            )
