"""
Behavioral specification: email thread continuity.

These tests describe the invariants that any email agent MUST maintain
to ensure conversations are properly threaded in the recipient's email client.

Key rule: every outbound reply must carry the thread_id from the triggering
inbound message. Omitting thread_id starts a new thread instead of replying,
breaking conversation history for both the agent and the customer.
"""
import pytest


class TestThreadIdPropagation:
    """Specify that thread_id must be preserved and propagated through reply chains."""

    def test_send_result_has_thread_id(self):
        """messages.send() must return a thread_id for use in subsequent replies.

        The thread_id from SendMessageResult is the value to pass back into
        messages.send(thread_id=...) for the next turn. Agents that discard
        this value will lose thread continuity on the second reply.
        """
        from commune.types import SendMessageResult

        result = SendMessageResult(
            id="doc_001",
            message_id="<msg001@mail.commune.email>",
            thread_id="t_abc123",
            status="queued",
        )
        assert result.thread_id is not None, "send() result must include thread_id"
        assert result.thread_id.startswith("t_"), "thread_id should have expected prefix format"

    def test_reply_requires_thread_id(self):
        """A reply to a customer must always include the original thread_id.

        Code that omits thread_id when replying is a correctness bug.
        The correct call signature always passes thread_id as a keyword argument.
        """
        from unittest.mock import MagicMock

        mock_client = MagicMock()
        mock_client.messages.send.return_value = MagicMock(
            thread_id="t_xyz",
            message_id="<msg002@mail.commune.email>",
            status="queued",
        )

        # Correct pattern: thread_id is explicitly passed
        mock_client.messages.send(
            to="customer@example.com",
            subject="Re: Help with order",
            text="Here is your answer...",
            inbox_id="i_support",
            thread_id="t_original",
        )

        call_kwargs = mock_client.messages.send.call_args.kwargs
        assert "thread_id" in call_kwargs, "Reply MUST include thread_id"
        assert call_kwargs["thread_id"] == "t_original"

    def test_thread_id_from_webhook_payload(self):
        """The thread_id required for replies is available in the webhook payload.

        A Commune webhook payload for an inbound message includes thread_id
        at data.thread_id. Agents MUST read from this path — not from a
        stored lookup — so that replies stay in the correct thread even when
        the customer starts a new conversation.
        """
        webhook_payload = {
            "event": "message.received",
            "data": {
                "thread_id": "t_abc123",
                "inbox_id": "i_support",
                "sender": "customer@example.com",
                "subject": "I need help",
                "text": "Please help me with my order",
            },
        }

        # The thread_id MUST be accessible at this exact path
        thread_id = webhook_payload["data"]["thread_id"]
        assert thread_id == "t_abc123"
        assert thread_id is not None, "webhook payload must provide thread_id"

    def test_thread_list_provides_thread_ids(self):
        """threads.list() must return Thread objects with thread_id for polling workflows.

        Agents that poll instead of using webhooks iterate threads.list().data
        and must find a usable thread_id on each Thread object. The last_direction
        field tells the agent whether a reply is needed.
        """
        from commune.types import Thread, ThreadList

        mock_thread = Thread(
            thread_id="t_abc123",
            subject="Customer inquiry",
            message_count=2,
            last_direction="inbound",
            last_message_at="2024-01-15T10:00:00Z",
        )
        thread_list = ThreadList(data=[mock_thread], has_more=False)

        assert len(thread_list.data) == 1
        assert thread_list.data[0].thread_id == "t_abc123"
        assert thread_list.data[0].last_direction == "inbound"

    def test_message_has_thread_id_field(self):
        """Every Message object must have a thread_id field for building reply context.

        When an agent loads a conversation via threads.messages(thread_id),
        each returned Message carries its own thread_id. This allows the agent
        to reconstruct the reply target even when messages are processed out of order.
        """
        from commune.types import Message, MessageMetadata, Participant

        msg = Message(
            message_id="<msg001@mail.example.com>",
            thread_id="t_abc123",
            direction="inbound",
            content="Hello, I need help with my order.",
            created_at="2024-01-15T10:00:00Z",
            metadata=MessageMetadata(created_at="2024-01-15T10:00:00Z"),
        )

        assert msg.thread_id == "t_abc123"
        assert msg.content == "Hello, I need help with my order."
        assert msg.direction == "inbound"
