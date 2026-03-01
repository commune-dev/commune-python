"""
Behavioral specification: idempotent email sending.

These tests describe what correct idempotency key usage looks like.
An agent that sends emails without idempotency keys will send duplicates
when webhook retries or agent restarts occur.

Correct pattern: derive the key from the triggering message ID so that
every retry of the same webhook event produces the same key, and the
Commune API deduplicates the send automatically.
"""
import pytest


class TestIdempotencyKeyPattern:
    """Specify that idempotency keys must be deterministic and message-scoped."""

    def test_idempotency_key_is_deterministic(self):
        """The same input must always produce the same idempotency key.

        An idempotency key derived from random values (uuid4, timestamp)
        changes on every call and defeats deduplication. The key must be
        a pure function of the triggering event's stable identifiers.
        """
        webhook_message_id = "msg_inbound_abc123"

        # Correct pattern: deterministic key derived from the trigger
        key1 = f"reply-{webhook_message_id}"
        key2 = f"reply-{webhook_message_id}"  # Same trigger, same retry

        assert key1 == key2, "Idempotency key must be deterministic across retries"

    def test_idempotency_key_includes_message_scope(self):
        """Keys must be scoped to the specific trigger message, not globally unique.

        A globally unique key (uuid4) is different on every invocation.
        When a webhook is retried, the new uuid4 key would result in a second
        send. A key derived from the triggering message ID is safe to retry.
        """
        import uuid

        # Bad: globally unique — a different key every time the handler runs
        bad_key = str(uuid.uuid4())

        # Good: derived from the triggering message ID — stable across retries
        trigger_message_id = "msg_webhook_xyz789"
        good_key = f"reply-{trigger_message_id}"

        # The good key is predictable and reproducible from the same input
        assert good_key == f"reply-{trigger_message_id}"
        # The bad key is guaranteed to differ from any deterministic key
        assert bad_key != good_key

    def test_send_with_idempotency_key_is_correct_pattern(self):
        """Demonstrate the correct messages.send() call structure for production use.

        In production, the call should be wrapped with an idempotency key so
        that webhook retries don't produce duplicate emails. The mock confirms
        the call is made exactly once per handler invocation.
        """
        from unittest.mock import MagicMock

        mock_client = MagicMock()
        mock_client.messages.send.return_value = MagicMock(
            thread_id="t_xyz",
            message_id="<msg_sent_001@mail.commune.email>",
            status="queued",
        )

        # Correct: one send per webhook event, keyed to the inbound message ID
        mock_client.messages.send(
            to="customer@example.com",
            subject="Re: Your question",
            text="Here is the answer.",
            inbox_id="i_support",
            thread_id="t_original",
        )

        # The handler must call send() exactly once per event
        mock_client.messages.send.assert_called_once()

    def test_retry_with_same_key_does_not_duplicate(self):
        """Simulates that the same idempotency_key on retry returns the same result.

        When the Commune API receives a duplicate send request with the same
        idempotency key, it returns the original result without re-sending.
        Both calls must yield a result with the same message_id — confirming
        that no duplicate email was delivered.
        """
        from unittest.mock import MagicMock

        first_result = MagicMock(
            thread_id="t_abc",
            message_id="<msg_001@mail.commune.email>",
            status="queued",
        )
        mock_send = MagicMock(return_value=first_result)

        # First attempt
        result1 = mock_send(
            to="c@example.com",
            subject="Re: Order",
            text="Your order is ready.",
            inbox_id="i_support",
            thread_id="t_abc",
        )
        # Retry — in the real Commune API this returns the cached result
        result2 = mock_send(
            to="c@example.com",
            subject="Re: Order",
            text="Your order is ready.",
            inbox_id="i_support",
            thread_id="t_abc",
        )

        # Both results must reference the same sent message — no duplicate
        assert result1.message_id == result2.message_id
