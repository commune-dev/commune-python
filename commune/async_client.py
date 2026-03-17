"""
Async Commune Python SDK — Email infrastructure for AI agents using asyncio.

This module provides AsyncCommuneClient, the async counterpart to CommuneClient.
Use this when building with FastAPI, asyncio, or any async Python framework where
blocking I/O would stall your event loop.

The API surface is identical to CommuneClient — every method is the same,
just prefixed with `await`. Switch between sync and async by changing the import
and adding `await` to each call.

Quick start:
    from commune import AsyncCommuneClient

    async def main():
        async with AsyncCommuneClient(api_key="comm_...") as client:
            inbox = await client.inboxes.create(local_part="support")
            print(inbox.address)  # → support@agents.commune.email

For sync usage (scripts, notebooks, simple backends), use CommuneClient from commune.client.

Framework integrations:
    - FastAPI: use directly in async route handlers
    - LangChain async agents: wrap with AsyncCallbackHandler
    - asyncio scripts: use async with or await client.close() explicitly

See: https://github.com/shanjai-raj/commune-cookbook for working examples.
"""

from __future__ import annotations

import os
from typing import Any, Optional
from urllib.parse import quote

from commune._async_http import AsyncHttpClient
from commune.types import (
    Attachment,
    DeleteResult,
    DeliveryEvent,
    DeliveryMetrics,
    DeliverySuppression,
    DomainDnsRecord,
    DomainVerificationResult,
    CreateDomainPayload,
    CreateInboxPayload,
    UpdateInboxPayload,
    SetInboxWebhookPayload,
    SearchResult,
    SendMessagePayload,
    SendMessageResult,
    UploadAttachmentPayload,
    AttachmentUpload,
    AttachmentUrl,
    Domain,
    Inbox,
    Message,
    Thread,
    ThreadList,
)


class _AsyncDomains:
    """Async domain management — register and verify custom sending domains.

    A domain is required before you can create inboxes with your own branding
    (e.g. support@yourcompany.com). Commune auto-assigns a shared domain
    (agents.commune.email) if you skip domain setup, which is fine for prototyping.

    Typical workflow for custom domains:
        1. await client.domains.create(name="yourcompany.com")
        2. await client.domains.records(domain_id) — get DNS records
        3. Add those records at your registrar
        4. await client.domains.verify(domain_id) — status → "verified"
        5. await client.inboxes.create(local_part="support", domain_id=domain_id)
    """

    def __init__(self, http: AsyncHttpClient):
        self._http = http

    async def list(self) -> list[Domain]:
        """List all domains registered in your Commune organization.

        Use this to discover your domain IDs before creating inboxes or
        to check which domains are verified vs. pending DNS propagation.

        Returns:
            List of Domain objects. Each has .id, .name, and .status
            ("verified" or "pending").

        Example:
            domains = await client.domains.list()
            verified = [d for d in domains if d.status == "verified"]
        """
        data = await self._http.get("/v1/domains")
        if isinstance(data, list):
            return [Domain.model_validate(d) for d in data]
        return [Domain.model_validate(d) for d in (data or [])]

    async def create(self, name: str, region: str | None = None) -> Domain:
        """Register a new custom sending domain with Commune.

        After creating, you must add DNS records and call .verify() before
        the domain can send email.

        Args:
            name: The domain name to register (e.g. "yourcompany.com").
            region: Optional deployment region (e.g. "us-east-1").

        Returns:
            Domain with .id (save for subsequent calls) and initial .records.

        Example:
            domain = await client.domains.create(name="myagency.com")
            records = await client.domains.records(domain.id)
        """
        payload = CreateDomainPayload(name=name, region=region)
        data = await self._http.post(
            "/v1/domains",
            json=payload.model_dump(exclude_none=True),
        )
        return Domain.model_validate(data)

    async def get(self, domain_id: str) -> Domain:
        """Get details and current verification status for a single domain.

        Args:
            domain_id: The domain ID from .list() or .create().

        Returns:
            Domain with current .status and .records verification state.

        Example:
            domain = await client.domains.get("d_abc123")
            if domain.status == "verified":
                inbox = await client.inboxes.create(local_part="support", domain_id=domain.id)
        """
        data = await self._http.get(f"/v1/domains/{quote(domain_id)}")
        return Domain.model_validate(data)

    async def verify(self, domain_id: str) -> DomainVerificationResult:
        """Trigger DNS verification for a domain.

        Call this after adding the required DNS records at your registrar.
        Commune checks MX, SPF, DKIM, and DMARC records.

        Args:
            domain_id: The domain ID to verify.

        Returns:
            DomainVerificationResult with .status ("verified" or "pending").

        Example:
            result = await client.domains.verify("d_abc123")
            if result.status == "verified":
                print("Domain ready — create inboxes now")
        """
        data = await self._http.post(f"/v1/domains/{quote(domain_id)}/verify")
        return DomainVerificationResult.model_validate(data)

    async def records(self, domain_id: str) -> list[DomainDnsRecord]:
        """Get the DNS records required to verify and activate a domain.

        Returns the exact records to add at your DNS registrar for MX routing,
        SPF authorization, and DKIM signing. Add all records before calling .verify().

        Args:
            domain_id: The domain ID.

        Returns:
            List of DomainDnsRecord objects with .type, .name, .value, .status.

        Example:
            records = await client.domains.records("d_abc123")
            for r in records:
                print(f"Add {r.type} record: {r.name} → {r.value}")
        """
        data = await self._http.get(f"/v1/domains/{quote(domain_id)}/records")
        records = data if isinstance(data, list) else []
        return [DomainDnsRecord.model_validate(record) for record in records]


class _AsyncInboxes:
    """Async inbox management — provision dedicated email addresses for agents.

    Each inbox is a real, deliverable email address. Create one per agent role,
    or one per tenant in multi-tenant applications.

    Create inboxes with or without specifying a domain. When no domain is
    provided, Commune automatically assigns your inbox to a shared domain
    (agents.commune.email) — no DNS setup required.
    """

    def __init__(self, http: AsyncHttpClient):
        self._http = http

    async def list(self, domain_id: Optional[str] = None) -> list[Inbox]:
        """List all inboxes, optionally scoped to a specific domain.

        Args:
            domain_id: Optional — list inboxes for a specific domain only.
                       If omitted, lists all inboxes across all domains.

        Returns:
            List of Inbox objects with .id and .address.

        Example — find the support inbox:
            inboxes = await client.inboxes.list()
            support = next(i for i in inboxes if "support" in i.local_part)
        """
        if domain_id:
            data = await self._http.get(f"/v1/domains/{quote(domain_id)}/inboxes")
        else:
            data = await self._http.get("/v1/inboxes")
        if isinstance(data, list):
            return [Inbox.model_validate(d) for d in data]
        return [Inbox.model_validate(d) for d in (data or [])]

    async def create(
        self,
        local_part: str,
        *,
        domain_id: Optional[str] = None,
        name: Optional[str] = None,
        webhook: Optional[dict[str, Any]] = None,
    ) -> Inbox:
        """Create a dedicated email inbox for an AI agent.

        Use this when your agent needs its own email address — for customer
        support, hiring pipelines, sales automation, or inter-agent task handoff.

        Args:
            local_part: The part before the @ symbol.
                "support" → support@agents.commune.email
                f"agent-{user_id}" → per-user isolation pattern
            domain_id: Domain to create the inbox under. Auto-resolved from
                Commune's shared domains if not provided.
            name: Human-readable label for the inbox (appears in dashboard).
            webhook: Optional webhook config dict.
                {"endpoint": "https://your-app.com/webhook", "events": ["inbound"]}

        Returns:
            Inbox with .id (use in all subsequent API calls) and .address
            (the full email address string).

        Example — customer support agent:
            inbox = await client.inboxes.create(local_part="support")
            print(inbox.address)  # → support@agents.commune.email

        Example — per-user agent isolation (multi-tenant):
            for user in users:
                inbox = await client.inboxes.create(
                    local_part=f"agent-{user.id}",
                    name=f"Agent for {user.name}",
                )
                await db.save(user_id=user.id, inbox_id=inbox.id)
        """
        payload = CreateInboxPayload(
            local_part=local_part,
            domain_id=domain_id,
            name=name,
            webhook=webhook,
        )
        data = await self._http.post(
            "/v1/inboxes",
            json=payload.model_dump(exclude_none=True),
        )
        return Inbox.model_validate(data)

    async def get(self, domain_id: str, inbox_id: str) -> Inbox:
        """Fetch the current state of a single inbox.

        Args:
            domain_id: The domain ID the inbox belongs to.
            inbox_id: The inbox ID (e.g. "i_abc123").

        Returns:
            Inbox with current configuration including webhook endpoint and secret.

        Example:
            inbox = await client.inboxes.get(domain_id="d_abc", inbox_id="i_xyz")
            print(inbox.webhook.secret)  # Use to verify webhook signatures
        """
        data = await self._http.get(
            f"/v1/domains/{quote(domain_id)}/inboxes/{quote(inbox_id)}"
        )
        return Inbox.model_validate(data)

    async def update(
        self,
        domain_id: str,
        inbox_id: str,
        *,
        local_part: Optional[str] = None,
        webhook: Optional[dict[str, Any]] = None,
        status: Optional[str] = None,
    ) -> Inbox:
        """Update an existing inbox's configuration.

        Only pass the fields you want to change — unspecified fields are
        left unchanged.

        Args:
            domain_id: The domain ID the inbox belongs to.
            inbox_id: The inbox ID to update.
            local_part: New local part (changes the email address prefix).
            webhook: New webhook configuration dict, or empty dict to remove webhook.
            status: New inbox status ("active" or "inactive").

        Returns:
            Updated Inbox reflecting the new configuration.

        Example — attach a webhook to an existing inbox:
            updated = await client.inboxes.update(
                domain_id="d_abc",
                inbox_id="i_xyz",
                webhook={
                    "endpoint": "https://myapp.com/webhook/email",
                    "events": ["inbound"],
                },
            )
        """
        payload = UpdateInboxPayload(
            local_part=local_part,
            webhook=webhook,
            status=status,
        )
        data = await self._http.put(
            f"/v1/domains/{quote(domain_id)}/inboxes/{quote(inbox_id)}",
            json=payload.model_dump(exclude_none=True),
        )
        return Inbox.model_validate(data)

    async def remove(self, domain_id: str, inbox_id: str) -> bool:
        """Permanently delete an inbox and all associated data.

        This action is irreversible. Consider using update(status="inactive")
        if you might need to restore the inbox later.

        Args:
            domain_id: The domain ID the inbox belongs to.
            inbox_id: The inbox ID to delete.

        Returns:
            True if the inbox was successfully deleted.

        Example:
            success = await client.inboxes.remove(
                domain_id="d_abc",
                inbox_id=await db.get_inbox_id(user_id),
            )
        """
        data = await self._http.delete(
            f"/v1/domains/{quote(domain_id)}/inboxes/{quote(inbox_id)}"
        )
        if isinstance(data, dict):
            return DeleteResult.model_validate(data).ok
        return True

    async def set_webhook(
        self,
        domain_id: str,
        inbox_id: str,
        *,
        endpoint: str,
        events: Optional[list[str]] = None,
    ) -> Inbox:
        """Attach or replace a webhook endpoint on an inbox.

        Webhooks deliver inbound email events to your agent in real time.
        Use commune.webhooks.verify_signature() in your handler to authenticate
        requests. The signing secret is on inbox.webhook.secret.

        Args:
            domain_id: The domain ID the inbox belongs to.
            inbox_id: The inbox ID to attach the webhook to.
            endpoint: Your HTTPS URL to receive POST requests when email arrives.
            events: List of event types. Defaults to ["inbound"] if omitted.

        Returns:
            Updated Inbox with webhook.secret.

        Example:
            inbox = await client.inboxes.set_webhook(
                domain_id="d_abc",
                inbox_id="i_xyz",
                endpoint="https://myapp.com/agent/webhook",
            )
            # Store inbox.webhook.secret for signature verification
        """
        payload = SetInboxWebhookPayload(endpoint=endpoint, events=events)
        data = await self._http.put(
            f"/v1/domains/{quote(domain_id)}/inboxes/{quote(inbox_id)}",
            json={"webhook": payload.model_dump(exclude_none=True)},
        )
        return Inbox.model_validate(data)


class _AsyncThreads:
    """Async thread management — browse and manage email conversations.

    A thread is a group of related email messages sharing a conversation history.
    Use threads to poll for new conversations, load history before replying,
    and track agent workflow state.
    """

    def __init__(self, http: AsyncHttpClient):
        self._http = http

    async def list(
        self,
        *,
        inbox_id: str | None = None,
        domain_id: str | None = None,
        limit: int = 20,
        cursor: str | None = None,
        order: str = "desc",
    ) -> ThreadList:
        """List email threads with cursor-based pagination.

        The primary way to poll for new conversations when not using webhooks.
        Filter by inbox_id to scope results to a single agent's mailbox.

        Args:
            inbox_id: Filter by inbox ID (recommended).
            domain_id: Alternatively, filter by domain.
            limit: Max results per page (1–100, default 20).
            cursor: Pagination cursor from a previous response's .next_cursor.
            order: "desc" (newest first, default) or "asc".

        Returns:
            ThreadList with .data, .next_cursor, and .has_more.

        Example — poll for customer messages:
            result = await client.threads.list(inbox_id=SUPPORT_INBOX_ID)
            for thread in result.data:
                if thread.last_direction == "inbound":
                    messages = await client.threads.messages(thread.thread_id)
                    reply = await agent.generate_reply(messages)
                    await client.messages.send(
                        to=extract_sender(messages),
                        text=reply,
                        inbox_id=SUPPORT_INBOX_ID,
                        thread_id=thread.thread_id,
                    )
        """
        params: dict[str, Any] = {"limit": limit, "order": order}
        if inbox_id:
            params["inbox_id"] = inbox_id
        if domain_id:
            params["domain_id"] = domain_id
        if cursor:
            params["cursor"] = cursor

        raw = await self._http.get("/v1/threads", params=params, unwrap_data=False)
        if isinstance(raw, dict):
            return ThreadList.model_validate(raw)
        if isinstance(raw, list):
            return ThreadList(data=[Thread.model_validate(t) for t in raw])
        return ThreadList()

    async def messages(
        self,
        thread_id: str,
        *,
        limit: int = 50,
        order: str = "asc",
    ) -> list[Message]:
        """Fetch all messages in a thread to reconstruct conversation history.

        Call this before generating a reply so your agent has full context.
        Pass the result to your LLM as conversation history.

        Args:
            thread_id: The thread ID. Get from threads.list(), a webhook
                       payload's "thread_id" field, or a Message object.
            limit: Max messages to return (1–1000, default 50).
            order: "asc" (oldest first, default — natural LLM format) or "desc".

        Returns:
            List of Message objects with .content, .direction, and .participants.

        Example — load context before replying:
            messages = await client.threads.messages(thread_id, order="asc")
            history = [
                {"role": "user" if m.direction == "inbound" else "assistant",
                 "content": m.content}
                for m in messages
            ]
            reply = await llm.achat(history)
        """
        data = await self._http.get(
            f"/v1/threads/{quote(thread_id)}/messages",
            params={"limit": limit, "order": order},
        )
        if isinstance(data, list):
            return [Message.model_validate(m) for m in data]
        return [Message.model_validate(m) for m in (data or [])]


class _AsyncMessages:
    """Async email sending — the core send primitive for agents.

    Use await client.messages.send() whenever your agent needs to send email.
    Always pass thread_id when replying to a customer to keep the conversation
    grouped in their email client.
    """

    def __init__(self, http: AsyncHttpClient):
        self._http = http

    async def send(
        self,
        *,
        to: str | list[str],
        subject: str,
        html: str | None = None,
        text: str | None = None,
        from_address: str | None = None,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        reply_to: str | None = None,
        thread_id: str | None = None,
        domain_id: str | None = None,
        inbox_id: str | None = None,
        attachments: list[str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> SendMessageResult:
        """Send an email from an agent inbox.

        The most important parameter is thread_id. Always pass thread_id when
        replying to a customer — this keeps the conversation grouped in the
        recipient's email client. Without thread_id, your reply starts a new
        email thread, breaking the conversation history visible to the customer.

        Args:
            to: Recipient email address or list of addresses.
            subject: Email subject line.
            html: HTML body. Provide text as a fallback.
            text: Plain-text body. Required if html is not provided.
            from_address: Override the "From" address (must be on a verified domain).
            cc: CC recipients (visible to all).
            bcc: BCC recipients (hidden from other recipients).
            reply_to: Address that receives replies if different from from_address.
            thread_id: Pass this to reply within an existing thread. Get from
                       webhook payload ("thread_id") or threads.list().
                       CRITICAL: Omitting this on replies breaks conversation threading.
            domain_id: Send from a specific domain's default inbox.
            inbox_id: Which inbox to send from (determines "From" address).
            attachments: List of attachment IDs from attachments.upload().
            headers: Custom SMTP headers dict.

        Returns:
            SendMessageResult with .message_id, .thread_id, and .status.

        Example — reply in thread (most common pattern):
            # In your FastAPI webhook handler:
            @app.post("/webhook")
            async def handle_email(request: Request):
                payload = await request.json()
                reply = await agent.generate_reply(payload["text"])
                await client.messages.send(
                    to=payload["sender"],
                    subject="Re: " + payload["subject"],
                    text=reply,
                    inbox_id=payload["inboxId"],
                    thread_id=payload["thread_id"],  # ← keeps conversation grouped
                )

        Example — send new email:
            await client.messages.send(
                to="candidate@example.com",
                subject="Following up on your application",
                text=personalized_message,
                inbox_id=hiring_inbox.id,
            )

        Raises:
            AuthenticationError: Invalid or missing API key.
            NotFoundError: inbox_id or thread_id does not exist.
            RateLimitError: Sending rate limit exceeded — back off and retry.
            ValidationError: Missing required fields (to, subject, text or html).
        """
        payload = SendMessagePayload(
            to=to,
            subject=subject,
            html=html,
            text=text,
            from_address=from_address,
            cc=cc,
            bcc=bcc,
            reply_to=reply_to,
            thread_id=thread_id,
            domain_id=domain_id,
            inbox_id=inbox_id,
            attachments=attachments,
            headers=headers,
        )
        data = await self._http.post(
            "/v1/messages/send",
            json=payload.model_dump(by_alias=True, exclude_none=True),
        )
        return SendMessageResult.model_validate(data)

    async def list(
        self,
        *,
        inbox_id: str | None = None,
        domain_id: str | None = None,
        sender: str | None = None,
        limit: int = 50,
        order: str = "desc",
        before: str | None = None,
        after: str | None = None,
    ) -> list[Message]:
        """List individual messages with filters.

        For conversation-level queries, prefer threads.list() which groups
        messages by thread. Use this for message-level filters like sender
        or time window.

        Provide at least one of inbox_id, domain_id, or sender.

        Args:
            inbox_id: Filter by inbox ID.
            domain_id: Filter by domain — returns messages across all inboxes.
            sender: Filter by sender email address.
            limit: Max results (1–1000, default 50).
            order: "asc" or "desc" (newest first, default).
            before: ISO 8601 datetime — only messages before this time.
            after: ISO 8601 datetime — only messages after this time.

        Returns:
            List of Message objects.

        Example — messages from a specific sender in the last 7 days:
            from datetime import datetime, timedelta, timezone
            cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
            messages = await client.messages.list(
                inbox_id="i_abc",
                sender="vip@client.com",
                after=cutoff,
            )
        """
        params: dict[str, Any] = {"limit": limit, "order": order}
        if inbox_id:
            params["inbox_id"] = inbox_id
        if domain_id:
            params["domain_id"] = domain_id
        if sender:
            params["sender"] = sender
        if before:
            params["before"] = before
        if after:
            params["after"] = after

        data = await self._http.get("/v1/messages", params=params)
        if isinstance(data, list):
            return [Message.model_validate(m) for m in data]
        return [Message.model_validate(m) for m in (data or [])]


class _AsyncAttachments:
    """Async attachment upload and retrieval — send files with agent emails.

    Attachments are uploaded separately from the email send, then referenced
    by ID. This two-step pattern lets you re-use attachments across multiple emails.

    Typical workflow:
        1. upload = await client.attachments.upload(content, filename, mime_type)
        2. await client.messages.send(..., attachments=[upload.attachment_id])
        3. url_info = await client.attachments.url(attachment_id)
    """

    def __init__(self, http: AsyncHttpClient):
        self._http = http

    async def upload(
        self,
        content: str,
        filename: str,
        mime_type: str,
    ) -> AttachmentUpload:
        """Upload a file attachment for use in outbound emails.

        Upload the file once, then pass the returned attachment_id to
        messages.send() in the attachments list.

        Args:
            content: Base64-encoded file content.
                     Encode with: base64.b64encode(file_bytes).decode("utf-8")
            filename: Original filename shown to the recipient (e.g. "report.pdf").
            mime_type: MIME type (e.g. "application/pdf", "image/png", "text/csv").

        Returns:
            AttachmentUpload with .attachment_id to pass to messages.send().

        Example:
            import base64, aiofiles
            async with aiofiles.open("report.pdf", "rb") as f:
                content = base64.b64encode(await f.read()).decode()
            upload = await client.attachments.upload(
                content=content,
                filename="report.pdf",
                mime_type="application/pdf",
            )
            await client.messages.send(
                to="manager@co.com", subject="Report",
                text="See attached.", inbox_id=inbox.id,
                attachments=[upload.attachment_id],
            )
        """
        payload = UploadAttachmentPayload(
            content=content,
            filename=filename,
            mime_type=mime_type,
        )
        data = await self._http.post(
            "/v1/attachments/upload",
            json=payload.model_dump(exclude_none=True),
        )
        return AttachmentUpload.model_validate(data)

    async def get(self, attachment_id: str) -> Attachment:
        """Get metadata for an attachment received in an inbound email.

        Use this when processing inbound emails that contain attachments.
        Attachment IDs are available on Message.attachments (list of IDs).

        Args:
            attachment_id: The attachment ID from Message.attachments.

        Returns:
            Attachment with .filename, .mime_type, and .size.

        Example:
            for attachment_id in message.attachments:
                meta = await client.attachments.get(attachment_id)
                if meta.mime_type == "application/pdf":
                    url_info = await client.attachments.url(attachment_id)
                    # Process the PDF
        """
        data = await self._http.get(f"/v1/attachments/{quote(attachment_id)}")
        return Attachment.model_validate(data)

    async def url(self, attachment_id: str, *, expires_in: int = 3600) -> AttachmentUrl:
        """Get a temporary signed download URL for an attachment.

        Use this to download attachment content or share a download link.
        URLs expire after the specified time.

        Args:
            attachment_id: The attachment ID.
            expires_in: URL expiration time in seconds (default 3600 = 1 hour).
                        Max is typically 86400 (24 hours).

        Returns:
            AttachmentUrl with .url (presigned download URL) and .filename.

        Example:
            url_info = await client.attachments.url(attachment_id)
            async with aiohttp.ClientSession() as session:
                async with session.get(url_info.url) as resp:
                    content = await resp.read()
        """
        data = await self._http.get(
            f"/v1/attachments/{quote(attachment_id)}/url",
            params={"expires_in": expires_in},
        )
        return AttachmentUrl.model_validate(data)


class _AsyncSearch:
    """Async full-text search across email threads."""

    def __init__(self, http: AsyncHttpClient):
        self._http = http

    async def threads(
        self,
        query: str,
        *,
        inbox_id: str | None = None,
        domain_id: str | None = None,
        limit: int = 20,
    ) -> list[SearchResult]:
        """Search across email threads by subject or content.

        Args:
            query: Search query string.
            inbox_id: Scope search to a single inbox (recommended).
            domain_id: Scope search to a domain.
            limit: Max results (1–100, default 20).

        Returns:
            List of SearchResult objects ordered by relevance.
        """
        params: dict[str, Any] = {"q": query, "limit": limit}
        if inbox_id:
            params["inbox_id"] = inbox_id
        if domain_id:
            params["domain_id"] = domain_id
        data = await self._http.get("/v1/search/threads", params=params)
        if isinstance(data, list):
            return [SearchResult.model_validate(r) for r in data]
        return [SearchResult.model_validate(r) for r in (data or [])]


class _AsyncDelivery:
    """Async deliverability monitoring."""

    def __init__(self, http: AsyncHttpClient):
        self._http = http

    async def metrics(
        self,
        *,
        inbox_id: str | None = None,
        domain_id: str | None = None,
        period: str = "7d",
    ) -> DeliveryMetrics:
        """Get email deliverability metrics.

        Args:
            inbox_id: Filter metrics to a specific inbox.
            domain_id: Filter metrics to a domain.
            period: Time window — "24h", "7d" (default), or "30d".

        Returns:
            DeliveryMetrics with sent, delivered, bounced, complained, failed counts
            and delivery_rate, bounce_rate, complaint_rate percentages.
        """
        params: dict[str, Any] = {"period": period}
        if inbox_id:
            params["inbox_id"] = inbox_id
        if domain_id:
            params["domain_id"] = domain_id
        data = await self._http.get("/v1/delivery/metrics", params=params)
        return DeliveryMetrics.model_validate(data)

    async def suppressions(
        self,
        *,
        inbox_id: str | None = None,
        domain_id: str | None = None,
        limit: int = 50,
    ) -> list[DeliverySuppression]:
        """List suppressed email addresses.

        Args:
            inbox_id: Filter suppressions to a specific inbox.
            domain_id: Filter suppressions to a domain.
            limit: Max results (default 50).

        Returns:
            List of DeliverySuppression objects with .email, .reason, .suppressed_at.
        """
        params: dict[str, Any] = {"limit": limit}
        if inbox_id:
            params["inbox_id"] = inbox_id
        if domain_id:
            params["domain_id"] = domain_id
        data = await self._http.get("/v1/delivery/suppressions", params=params)
        if isinstance(data, list):
            return [DeliverySuppression.model_validate(s) for s in data]
        return [DeliverySuppression.model_validate(s) for s in (data or [])]

    async def events(
        self,
        *,
        message_id: str | None = None,
        inbox_id: str | None = None,
        domain_id: str | None = None,
        event_type: str | None = None,
        limit: int = 50,
    ) -> list[DeliveryEvent]:
        """Get the delivery event log for messages.

        Args:
            message_id: Filter events for a specific message.
            inbox_id: Filter events for all messages from an inbox.
            domain_id: Filter events for all messages from a domain.
            event_type: Filter by type: "sent", "delivered", "bounced",
                        "complained", or "failed".
            limit: Max results (default 50).

        Returns:
            List of DeliveryEvent objects with .event_type, .recipient, .timestamp.
        """
        params: dict[str, Any] = {"limit": limit}
        if message_id:
            params["message_id"] = message_id
        if inbox_id:
            params["inbox_id"] = inbox_id
        if domain_id:
            params["domain_id"] = domain_id
        if event_type:
            params["event_type"] = event_type
        data = await self._http.get("/v1/delivery/events", params=params)
        if isinstance(data, list):
            return [DeliveryEvent.model_validate(e) for e in data]
        return [DeliveryEvent.model_validate(e) for e in (data or [])]


class AsyncCommuneClient:
    """Async Commune SDK client — email infrastructure for AI agents using asyncio.

    Identical API to CommuneClient but all methods are async. Use this when
    building with FastAPI, asyncio, or any async Python framework where blocking
    network I/O would stall your event loop.

    Initialize once at application startup and reuse across requests. It is
    safe to share across coroutines.

    Args:
        api_key: Your Commune API key (starts with "comm_").
                 Reads from COMMUNE_API_KEY env var if not passed directly.
                 Raises ValueError immediately if no key is found.
        base_url: Override the API base URL for self-hosted deployments.
                  Default: https://api.commune.email
        timeout: Request timeout in seconds (default 30).

    Raises:
        ValueError: If no API key is provided and COMMUNE_API_KEY is not set.

    Example — FastAPI integration:
        from fastapi import FastAPI, Request
        from commune import AsyncCommuneClient
        from commune.webhooks import verify_signature
        import json, os

        app = FastAPI()
        client = AsyncCommuneClient()  # reads COMMUNE_API_KEY from env

        @app.post("/webhook")
        async def handle_email(request: Request):
            body = await request.body()
            verify_signature(
                payload=body,
                signature=request.headers["x-commune-signature"],
                secret=os.environ["COMMUNE_WEBHOOK_SECRET"],
                timestamp=request.headers["x-commune-timestamp"],
            )
            payload = json.loads(body)
            reply = await agent.generate_reply(payload["text"])
            await client.messages.send(
                to=payload["sender"],
                subject="Re: " + payload["subject"],
                text=reply,
                inbox_id=payload["inboxId"],
                thread_id=payload["thread_id"],
            )
            return {"ok": True}

    Example — async context manager (auto-closes HTTP connection):
        async with AsyncCommuneClient(api_key="comm_...") as client:
            inbox = await client.inboxes.create(local_part="support")
            await client.messages.send(
                to="user@example.com",
                subject="Hello",
                text="Message from your agent",
                inbox_id=inbox.id,
            )

    Example — startup/shutdown lifecycle (FastAPI lifespan):
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            app.state.commune = AsyncCommuneClient()
            yield
            await app.state.commune.close()

        app = FastAPI(lifespan=lifespan)
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        timeout: float = 30.0,
    ):
        resolved_key = api_key or os.environ.get("COMMUNE_API_KEY") or ""
        if not resolved_key:
            raise ValueError(
                "No API key provided. Pass api_key= or set the COMMUNE_API_KEY "
                "environment variable."
            )
        self._http = AsyncHttpClient(api_key=resolved_key, base_url=base_url, timeout=timeout)
        self.domains = _AsyncDomains(self._http)
        self.inboxes = _AsyncInboxes(self._http)
        self.threads = _AsyncThreads(self._http)
        self.messages = _AsyncMessages(self._http)
        self.attachments = _AsyncAttachments(self._http)
        self.search = _AsyncSearch(self._http)
        self.delivery = _AsyncDelivery(self._http)

    async def close(self) -> None:
        """Close the underlying async HTTP connection pool.

        Call this when shutting down to release connections. Not needed when
        using the client as an async context manager (async with ...).

        Example:
            client = AsyncCommuneClient()
            try:
                # ... use client ...
            finally:
                await client.close()
        """
        await self._http.close()

    async def __aenter__(self) -> AsyncCommuneClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
