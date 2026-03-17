"""
Commune Python SDK — Email infrastructure for AI agents.

This module provides CommuneClient, the main entry point for all Commune operations.
Use this when you want your AI agent to:

- Have a real email address (client.inboxes.create)
- Send email from that address (client.messages.send)
- Receive and reply to emails in threaded conversations (webhook + client.messages.send with thread_id)
- Search email history with natural language (client.search.threads(query))
- Extract structured data from inbound emails automatically (client.inboxes.update with extraction_schema)
- Handle file attachments (client.attachments.upload, client.attachments.get)

Quick start:
    from commune import CommuneClient

    client = CommuneClient(api_key="comm_...")
    inbox = client.inboxes.create(local_part="support")
    print(inbox.address)  # → support@agents.commune.email

For async usage (FastAPI, asyncio), use AsyncCommuneClient from commune.async_client.

Framework integrations:
    - LangChain: wrap methods with @tool decorator
    - CrewAI: subclass BaseTool for each operation
    - OpenAI Agents SDK: use @function_tool decorator
    - Claude: define tool schemas matching method signatures

See: https://github.com/shanjai-raj/commune-cookbook for working examples.
"""

from __future__ import annotations

import os
from typing import Any, Optional
from urllib.parse import quote

from commune._http import HttpClient
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


class _Domains:
    """Domain management — register and verify custom sending domains.

    A domain is required before you can create inboxes with your own branding
    (e.g. support@yourcompany.com). Commune auto-assigns a shared domain
    (agents.commune.email) if you skip domain setup, which is fine for prototyping.

    Typical workflow for custom domains:
        1. client.domains.create(name="yourcompany.com")
        2. client.domains.records(domain_id) — get DNS TXT/MX/DKIM records
        3. Add those records at your DNS registrar (Cloudflare, Route53, etc.)
        4. client.domains.verify(domain_id) — Commune checks DNS; status → "verified"
        5. client.inboxes.create(local_part="support", domain_id=domain_id)

    Example::

        # List all domains
        domains = client.domains.list()

        # Create a domain
        domain = client.domains.create(name="example.com")

        # Verify DNS
        result = client.domains.verify(domain.id)

        # Get DNS records to configure
        records = client.domains.records(domain.id)
    """

    def __init__(self, http: HttpClient):
        self._http = http

    def list(self) -> list[Domain]:
        """List all domains registered in your Commune organization.

        Use this to discover your domain IDs before creating inboxes or
        to check which domains are verified vs. pending DNS propagation.

        Returns:
            List of Domain objects. Each has .id (use in API calls),
            .name (the domain string), and .status ("verified" or "pending").

        Example:
            domains = client.domains.list()
            verified = [d for d in domains if d.status == "verified"]
        """
        data = self._http.get("/v1/domains")
        if isinstance(data, list):
            return [Domain.model_validate(d) for d in data]
        return [Domain.model_validate(d) for d in (data or [])]

    def create(self, name: str, region: str | None = None) -> Domain:
        """Register a new custom sending domain with Commune.

        After creating, you must add DNS records (from .records()) to your
        registrar and then call .verify() before the domain can send email.
        DNS propagation typically takes minutes to hours depending on your TTL.

        Args:
            name: The domain name to register (e.g. "yourcompany.com").
                  Must be a domain you control — Commune will need to verify
                  MX and DKIM records.
            region: Optional deployment region (e.g. "us-east-1"). Defaults
                    to the region closest to your account.

        Returns:
            Domain with .id (save this for subsequent API calls) and
            .records (DNS records to configure at your registrar).

        Example:
            domain = client.domains.create(name="myagency.com")
            records = client.domains.records(domain.id)
            # Add records to DNS, then:
            client.domains.verify(domain.id)
        """
        payload = CreateDomainPayload(name=name, region=region)
        data = self._http.post(
            "/v1/domains",
            json=payload.model_dump(exclude_none=True),
        )
        return Domain.model_validate(data)

    def get(self, domain_id: str) -> Domain:
        """Get details and current verification status for a single domain.

        Use this to poll verification status after adding DNS records, or to
        retrieve the domain's inbox list and webhook configuration.

        Args:
            domain_id: The domain ID (e.g. "d_abc123") from .list() or .create().

        Returns:
            Domain with current .status ("verified", "pending", "failed") and
            .records showing which DNS entries are configured correctly.

        Example:
            domain = client.domains.get("d_abc123")
            if domain.status == "verified":
                # Safe to create inboxes under this domain
                inbox = client.inboxes.create(local_part="support", domain_id=domain.id)
        """
        data = self._http.get(f"/v1/domains/{quote(domain_id)}")
        return Domain.model_validate(data)

    def verify(self, domain_id: str) -> DomainVerificationResult:
        """Trigger DNS verification for a domain.

        Call this after adding the required DNS records at your registrar.
        Commune checks MX, SPF, DKIM, and DMARC records. If all pass,
        domain status changes to "verified" and inboxes can send email.

        DNS propagation can take up to 48 hours, but usually completes within
        15 minutes for major registrars. Re-call verify() to re-check status.

        Args:
            domain_id: The domain ID to verify.

        Returns:
            DomainVerificationResult with .status ("verified" or "pending")
            and .id of the domain.

        Example:
            # After setting DNS records:
            result = client.domains.verify("d_abc123")
            if result.status == "verified":
                print("Domain ready — create inboxes now")
            else:
                print("DNS not yet propagated — try again in a few minutes")
        """
        data = self._http.post(f"/v1/domains/{quote(domain_id)}/verify")
        return DomainVerificationResult.model_validate(data)

    def records(self, domain_id: str) -> list[DomainDnsRecord]:
        """Get the DNS records required to verify and activate a domain.

        Returns the exact records to add at your DNS registrar (Cloudflare,
        Route53, GoDaddy, etc.) for MX routing, SPF authorization, and
        DKIM signing. Add all records before calling .verify().

        Args:
            domain_id: The domain ID.

        Returns:
            List of DomainDnsRecord objects. Each has:
              .type  — "MX", "TXT", "CNAME"
              .name  — the hostname to set (e.g. "_dkim._domainkey")
              .value — the record value to configure
              .status — "verified" or "pending" per-record

        Example:
            records = client.domains.records("d_abc123")
            for r in records:
                print(f"Add {r.type} record: {r.name} → {r.value}")
                print(f"  Status: {r.status}")
        """
        data = self._http.get(f"/v1/domains/{quote(domain_id)}/records")
        records = data if isinstance(data, list) else []
        return [DomainDnsRecord.model_validate(record) for record in records]


class _Inboxes:
    """Inbox management — provision dedicated email addresses for agents.

    Each inbox is a real, deliverable email address. Create one per agent role,
    or one per tenant in multi-tenant applications. The inbox is the core
    primitive: it owns an address, receives inbound email, and is the "From"
    address when your agent sends.

    Create inboxes with or without specifying a domain. When no domain is
    provided, Commune automatically assigns your inbox to a shared domain
    (agents.commune.email) — no DNS setup required, useful for prototyping.

    Example::

        # Simplest — shared domain is auto-resolved
        inbox = client.inboxes.create(local_part="support")
        print(inbox.address)  # → support@agents.commune.email

        # Custom domain (must be verified first)
        inbox = client.inboxes.create(local_part="support", domain_id="d_abc")

        # List all inboxes across all domains
        inboxes = client.inboxes.list()
    """

    def __init__(self, http: HttpClient):
        self._http = http

    def list(self, domain_id: Optional[str] = None) -> list[Inbox]:
        """List all inboxes, optionally scoped to a specific domain.

        Use this to discover existing inbox IDs, audit your agent email
        addresses, or populate a dashboard of active agents.

        Args:
            domain_id: Optional — list inboxes for a specific domain only.
                       If omitted, lists all inboxes across all your domains
                       (including shared Commune domains).

        Returns:
            List of Inbox objects. Each has .id (use in API calls) and
            .address (the full email address string).

        Example — find the support inbox:
            inboxes = client.inboxes.list()
            support = next(i for i in inboxes if "support" in i.local_part)
            print(support.address)

        Example — inboxes for a specific domain:
            inboxes = client.inboxes.list(domain_id="d_abc123")
        """
        if domain_id:
            data = self._http.get(f"/v1/domains/{quote(domain_id)}/inboxes")
        else:
            data = self._http.get("/v1/inboxes")
        if isinstance(data, list):
            return [Inbox.model_validate(d) for d in data]
        return [Inbox.model_validate(d) for d in (data or [])]

    def create(
        self,
        local_part: str,
        *,
        domain_id: Optional[str] = None,
        name: Optional[str] = None,
        webhook: Optional[dict[str, Any]] = None,
    ) -> Inbox:
        """Create a dedicated email inbox for an AI agent.

        Use this when your agent needs its own email address — for customer
        support, hiring pipelines, sales automation, inter-agent task handoff,
        or any scenario where an agent needs to send and receive email.

        Each inbox is a real, deliverable email address. By default it's created
        under a shared Commune domain so you can start without DNS setup. Pass
        domain_id to use your own verified domain instead.

        Args:
            local_part: The part before the @ symbol.
                "support" → support@agents.commune.email
                "hiring-agent" → hiring-agent@agents.commune.email
                f"agent-{user_id}" → per-user isolation pattern
            domain_id: Domain to create the inbox under. Auto-resolved from
                Commune's shared domains if not provided. Use client.domains.list()
                to find your verified domain IDs.
            name: Human-readable label for the inbox (appears in dashboard).
                  Does not affect the email address.
            webhook: Optional webhook config dict for real-time inbound email delivery.
                {"endpoint": "https://your-app.com/webhook", "events": ["inbound"]}
                Set this if you want push delivery; otherwise poll with threads.list().

        Returns:
            Inbox with:
              .id      — use this in all subsequent API calls
              .address — the full email address (e.g. "support@agents.commune.email")
              .webhook — webhook configuration including the signing secret

        Example — customer support agent:
            inbox = client.inboxes.create(local_part="support")
            print(inbox.address)  # → support@agents.commune.email

        Example — with webhook for real-time delivery:
            inbox = client.inboxes.create(
                local_part="triage",
                webhook={"endpoint": "https://myapp.com/webhook/email"},
            )
            # Store inbox.webhook.secret to verify incoming webhook signatures

        Example — per-user agent isolation (multi-tenant):
            for user in users:
                inbox = client.inboxes.create(
                    local_part=f"agent-{user.id}",
                    name=f"Agent for {user.name}",
                )
                db.save(user_id=user.id, inbox_id=inbox.id)

        Example — CrewAI crew with dedicated inboxes per role:
            triage_inbox  = client.inboxes.create(local_part="triage")
            billing_inbox = client.inboxes.create(local_part="billing")
            tech_inbox    = client.inboxes.create(local_part="tech-support")
        """
        payload = CreateInboxPayload(
            local_part=local_part,
            domain_id=domain_id,
            name=name,
            webhook=webhook,
        )

        # Use top-level POST /v1/inboxes (auto-resolves domain)
        data = self._http.post(
            "/v1/inboxes",
            json=payload.model_dump(exclude_none=True),
        )
        return Inbox.model_validate(data)

    def get(self, domain_id: str, inbox_id: str) -> Inbox:
        """Fetch the current state of a single inbox.

        Use this to refresh inbox metadata after updates, check webhook
        configuration, or retrieve the signing secret for a specific inbox.

        Args:
            domain_id: The domain ID the inbox belongs to.
                       Use client.inboxes.list() if you don't have this.
            inbox_id: The inbox ID (e.g. "i_abc123").

        Returns:
            Inbox with current configuration including webhook endpoint,
            extraction_schema, and status.

        Example:
            inbox = client.inboxes.get(domain_id="d_abc", inbox_id="i_xyz")
            print(inbox.address)
            print(inbox.webhook.secret)  # Use to verify inbound webhook signatures
        """
        data = self._http.get(
            f"/v1/domains/{quote(domain_id)}/inboxes/{quote(inbox_id)}"
        )
        return Inbox.model_validate(data)

    def update(
        self,
        domain_id: str,
        inbox_id: str,
        *,
        local_part: Optional[str] = None,
        webhook: Optional[dict[str, Any]] = None,
        status: Optional[str] = None,
    ) -> Inbox:
        """Update an existing inbox's configuration.

        Use this to attach or change a webhook endpoint, rename the inbox's
        local part (email address prefix), add an extraction_schema for
        auto-parsing inbound emails, or deactivate the inbox.

        Only pass the fields you want to change — unspecified fields are
        left unchanged.

        Args:
            domain_id: The domain ID the inbox belongs to.
            inbox_id: The inbox ID to update.
            local_part: New local part (changes the email address).
                        "support" → "billing" changes address from
                        support@domain.com to billing@domain.com.
            webhook: New webhook configuration dict.
                {"endpoint": "https://new-url.com/webhook", "events": ["inbound"]}
                Pass an empty dict to remove the webhook.
            status: New inbox status. Use "active" or "inactive" to
                    enable/disable email delivery without deleting the inbox.

        Returns:
            Updated Inbox reflecting the new configuration.

        Example — attach a webhook to an existing inbox:
            updated = client.inboxes.update(
                domain_id="d_abc",
                inbox_id="i_xyz",
                webhook={
                    "endpoint": "https://myapp.com/webhook/email",
                    "events": ["inbound"],
                },
            )
            print(updated.webhook.secret)  # Save this for signature verification

        Example — add an extraction schema to auto-parse inbound emails:
            client.inboxes.update(
                domain_id="d_abc",
                inbox_id="i_xyz",
                webhook={
                    "endpoint": "https://myapp.com/webhook",
                    "extractionSchema": {
                        "type": "object",
                        "properties": {
                            "urgency": {"type": "string"},
                            "topic": {"type": "string"},
                        },
                    },
                },
            )
            # Inbound messages will include .metadata.extracted_data with parsed fields
        """
        payload = UpdateInboxPayload(
            local_part=local_part,
            webhook=webhook,
            status=status,
        )
        data = self._http.put(
            f"/v1/domains/{quote(domain_id)}/inboxes/{quote(inbox_id)}",
            json=payload.model_dump(exclude_none=True),
        )
        return Inbox.model_validate(data)

    def remove(self, domain_id: str, inbox_id: str) -> bool:
        """Permanently delete an inbox and all associated data.

        Use this to clean up agent inboxes that are no longer needed —
        for example when a tenant churns or a temporary workflow completes.
        This action is irreversible: the email address is freed and threads
        are deleted. Consider using update(status="inactive") instead if
        you might need to restore the inbox later.

        Args:
            domain_id: The domain ID the inbox belongs to.
            inbox_id: The inbox ID to delete.

        Returns:
            True if the inbox was successfully deleted.

        Example:
            # Decommission a trial user's agent inbox
            success = client.inboxes.remove(
                domain_id="d_abc",
                inbox_id=db.get_inbox_id(user_id),
            )
            if success:
                db.clear_inbox_id(user_id)
        """
        data = self._http.delete(
            f"/v1/domains/{quote(domain_id)}/inboxes/{quote(inbox_id)}"
        )
        if isinstance(data, dict):
            return DeleteResult.model_validate(data).ok
        return True

    def set_webhook(
        self,
        domain_id: str,
        inbox_id: str,
        *,
        endpoint: str,
        events: Optional[list[str]] = None,
    ) -> Inbox:
        """Attach or replace a webhook endpoint on an inbox.

        Webhooks deliver inbound email events to your agent in real time.
        When email arrives at the inbox, Commune POSTs the full message payload
        to your endpoint within seconds — no polling required.

        Use commune.webhooks.verify_signature() in your handler to authenticate
        the request before processing. The signing secret is on inbox.webhook.secret.

        Args:
            domain_id: The domain ID the inbox belongs to.
            inbox_id: The inbox ID to attach the webhook to.
            endpoint: Your HTTPS URL to receive POST requests when email arrives.
                      Must be publicly reachable. Use a tool like ngrok during
                      local development.
            events: List of event types to subscribe to.
                    Defaults to ["inbound"] if omitted.
                    Available: "inbound", "delivery", "bounce"

        Returns:
            Updated Inbox with webhook.secret — save this value to verify
            incoming webhook requests.

        Example:
            inbox = client.inboxes.set_webhook(
                domain_id="d_abc",
                inbox_id="i_xyz",
                endpoint="https://myapp.com/agent/webhook",
                events=["inbound"],
            )
            # Store the secret somewhere secure:
            os.environ["COMMUNE_WEBHOOK_SECRET"] = inbox.webhook.secret
        """
        payload = SetInboxWebhookPayload(endpoint=endpoint, events=events)
        data = self._http.put(
            f"/v1/domains/{quote(domain_id)}/inboxes/{quote(inbox_id)}",
            json={"webhook": payload.model_dump(exclude_none=True)},
        )
        return Inbox.model_validate(data)


class _Threads:
    """Thread (conversation) management — browse and manage email conversations.

    A thread is a group of related email messages sharing a conversation history.
    Every email belongs to a thread. When you reply using thread_id in messages.send(),
    the reply is added to the existing thread and rendered as a continuation in the
    recipient's email client (Gmail, Outlook, Apple Mail).

    Use threads to:
    - Poll for new conversations (instead of webhooks)
    - Load full conversation history before generating a reply
    - Update a thread's status to track agent workflow state

    Example::

        # List threads for an inbox (paginated)
        result = client.threads.list(inbox_id="i_abc123", limit=20)
        for thread in result.data:
            print(thread.thread_id, thread.subject, thread.snippet)

        # Get next page
        if result.has_more:
            next_page = client.threads.list(inbox_id="i_abc123", cursor=result.next_cursor)

        # Get all messages in a thread (full conversation history)
        messages = client.threads.messages(thread_id)
    """

    def __init__(self, http: HttpClient):
        self._http = http

    def list(
        self,
        *,
        inbox_id: str | None = None,
        domain_id: str | None = None,
        limit: int = 20,
        cursor: str | None = None,
        order: str = "desc",
    ) -> ThreadList:
        """List email threads with cursor-based pagination.

        The primary way to poll for new conversations when you're not using
        webhooks. Filter by inbox_id to scope results to a single agent's
        mailbox. Use the cursor from the response to paginate through all threads.

        Args:
            inbox_id: Filter by inbox ID (recommended — avoids mixing threads
                      from multiple agent inboxes). Use client.inboxes.list()
                      to find inbox IDs.
            domain_id: Alternatively, filter by domain (returns threads from
                       all inboxes under the domain).
            limit: Max results per page (1–100, default 20). Use smaller limits
                   for real-time polling, larger for bulk processing.
            cursor: Pagination cursor from a previous response's .next_cursor.
                    Omit to start from the most recent threads.
            order: Sort order — "desc" (newest first, default) for a live feed,
                   "asc" for chronological processing.

        Returns:
            ThreadList with:
              .data        — list of Thread summaries
              .next_cursor — pass to cursor= on next call (None if last page)
              .has_more    — True if more pages exist

        Example — poll for unread threads:
            result = client.threads.list(inbox_id=SUPPORT_INBOX_ID, limit=10)
            for thread in result.data:
                if thread.last_direction == "inbound":
                    # Customer sent the last message — agent should reply
                    messages = client.threads.messages(thread.thread_id)
                    reply = generate_reply(messages)
                    client.messages.send(
                        to=extract_sender(messages),
                        text=reply,
                        inbox_id=SUPPORT_INBOX_ID,
                        thread_id=thread.thread_id,
                    )

        Example — paginate through all threads:
            cursor = None
            all_threads = []
            while True:
                page = client.threads.list(inbox_id=inbox_id, cursor=cursor, limit=100)
                all_threads.extend(page.data)
                if not page.has_more:
                    break
                cursor = page.next_cursor
        """
        params: dict[str, Any] = {"limit": limit, "order": order}
        if inbox_id:
            params["inbox_id"] = inbox_id
        if domain_id:
            params["domain_id"] = domain_id
        if cursor:
            params["cursor"] = cursor

        raw = self._http.get("/v1/threads", params=params, unwrap_data=False)
        if isinstance(raw, dict):
            return ThreadList.model_validate(raw)
        if isinstance(raw, list):
            return ThreadList(data=[Thread.model_validate(t) for t in raw])
        return ThreadList()

    def messages(
        self,
        thread_id: str,
        *,
        limit: int = 50,
        order: str = "asc",
    ) -> list[Message]:
        """Fetch all messages in a thread to reconstruct conversation history.

        Call this before generating a reply so your agent has full context —
        the entire back-and-forth conversation, not just the latest message.
        Pass the result to your LLM as conversation history.

        Args:
            thread_id: The thread (conversation) ID. Get from threads.list(),
                       a webhook payload's "thread_id" field, or a Message object.
            limit: Max messages to return (1–1000, default 50). Most conversations
                   fit in the default limit. Increase for long-running threads.
            order: "asc" (oldest first, default) gives chronological order which
                   is the natural format for LLM conversation history.
                   "desc" gives newest-first for quick access to the latest message.

        Returns:
            List of Message objects representing the full conversation.
            Each message has .content (plain text), .content_html, .direction
            ("inbound" or "outbound"), .participants, and .metadata.

        Example — load context before replying:
            messages = client.threads.messages(thread_id, order="asc")

            # Format for LLM context
            history = [
                {
                    "role": "user" if m.direction == "inbound" else "assistant",
                    "content": m.content,
                }
                for m in messages
            ]
            reply = llm.chat(history + [{"role": "user", "content": "Reply helpfully"}])

        Example — extract just the latest customer message:
            messages = client.threads.messages(thread_id, order="desc", limit=1)
            latest = messages[0]
            customer_text = latest.content
        """
        data = self._http.get(
            f"/v1/threads/{quote(thread_id)}/messages",
            params={"limit": limit, "order": order},
        )
        if isinstance(data, list):
            return [Message.model_validate(m) for m in data]
        return [Message.model_validate(m) for m in (data or [])]


class _Messages:
    """Email sending and listing — the core send primitive for agents.

    Use client.messages.send() whenever your agent needs to send email.
    The most important parameter is thread_id — always pass it when replying
    to a customer to keep the conversation grouped in their email client.

    Example::

        # Reply in an existing thread (most common)
        client.messages.send(
            to="customer@example.com",
            text="Here is what I found...",
            inbox_id="i_abc123",
            thread_id="t_xyz789",  # keeps conversation grouped
        )

        # Start a new conversation
        client.messages.send(
            to="lead@example.com",
            subject="Following up on your inquiry",
            html="<p>Hi! I wanted to follow up...</p>",
            inbox_id="i_abc123",
        )
    """

    def __init__(self, http: HttpClient):
        self._http = http

    def send(
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
        recipient's email client (Gmail, Outlook, Apple Mail). Without thread_id,
        your reply starts a new email thread, breaking the conversation history
        visible to the customer.

        Args:
            to: Recipient email address or list of addresses.
                Single: "user@example.com"
                Multiple: ["alice@co.com", "bob@co.com"]
            subject: Email subject line. For replies, pass the original subject
                     (Commune will not auto-prefix "Re:" — do this yourself if needed).
            html: HTML body. Use for rich formatting, styling, and clickable links.
                  Provide text as a fallback for email clients that don't render HTML.
            text: Plain-text body. Always provide this alongside html for maximum
                  compatibility. Required if html is not provided.
            from_address: Override the "From" address. Defaults to the inbox address.
                          Must be an address on a verified domain.
            cc: CC recipients (visible to all recipients).
            bcc: BCC recipients (hidden from other recipients).
            reply_to: Address that receives replies if different from from_address.
                      Useful when sending from a no-reply address but wanting replies
                      to go to a monitored inbox.
            thread_id: Pass this to reply within an existing thread. Get thread_id
                       from the webhook payload ("thread_id" key) or from threads.list().
                       Omit only when starting a brand new conversation.
                       CRITICAL: Missing thread_id on replies breaks conversation threading
                       in the recipient's email client.
            domain_id: Send from a specific domain (uses domain's default inbox).
                       Use inbox_id instead for more precise control.
            inbox_id: Which inbox to send from. Determines the "From" address the
                      recipient sees. Required unless domain_id is set or you have
                      only one inbox.
            attachments: List of attachment IDs from attachments.upload().
                         Upload files first, then pass the returned IDs here.
            headers: Custom SMTP headers dict. Rarely needed — use for special
                     cases like List-Unsubscribe or X-Priority.

        Returns:
            SendMessageResult with:
              .message_id — SMTP message ID for delivery tracking
              .thread_id  — the thread this message belongs to (useful when
                            you didn't pass thread_id and need to save it)
              .status     — delivery status ("queued", "sent")

        Example — reply in thread (most common pattern):
            # In your webhook handler:
            thread_id = payload["thread_id"]
            inbox_id  = payload["inboxId"]
            sender    = payload["sender"]

            reply_text = agent.generate_reply(payload["text"])

            client.messages.send(
                to=sender,
                subject="Re: " + payload["subject"],
                text=reply_text,
                inbox_id=inbox_id,
                thread_id=thread_id,  # ← keeps conversation grouped
            )

        Example — send new email (outreach, notification):
            client.messages.send(
                to="candidate@example.com",
                subject="Following up on your application",
                text=personalized_message,
                inbox_id=hiring_inbox.id,
            )

        Example — HTML email with attachment:
            upload = client.attachments.upload(
                content=base64.b64encode(pdf_bytes).decode(),
                filename="report.pdf",
                mime_type="application/pdf",
            )
            client.messages.send(
                to="user@example.com",
                subject="Your weekly report",
                html="<p>See the attached PDF for your report.</p>",
                text="See the attached PDF for your report.",
                inbox_id=digest_inbox.id,
                attachments=[upload.attachment_id],
            )

        Example — send to multiple recipients with BCC:
            client.messages.send(
                to=["alice@co.com", "bob@co.com"],
                bcc=["manager@co.com"],
                subject="Project update",
                text="Here is the latest status...",
                inbox_id=inbox.id,
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
        data = self._http.post(
            "/v1/messages/send",
            json=payload.model_dump(by_alias=True, exclude_none=True),
        )
        return SendMessageResult.model_validate(data)

    def list(
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

        Use this for message-level queries — filtering by sender, time window,
        or inbox. For conversation-level queries, prefer threads.list() which
        groups messages by thread and is more efficient for most agent workflows.

        Provide at least one of inbox_id, domain_id, or sender to scope results.

        Args:
            inbox_id: Filter by inbox ID — returns only messages in this inbox.
            domain_id: Filter by domain — returns messages across all inboxes
                       in the domain.
            sender: Filter by sender email address (e.g. "customer@example.com").
                    Useful for looking up all messages from a specific contact.
            limit: Max results (1–1000, default 50).
            order: "asc" (oldest first) or "desc" (newest first, default).
            before: ISO 8601 datetime — only messages before this time.
                    Example: "2024-01-15T12:00:00Z"
            after: ISO 8601 datetime — only messages after this time.
                   Example: "2024-01-01T00:00:00Z"

        Returns:
            List of Message objects, each with .content, .direction,
            .participants, and .metadata (includes spam scores, extraction results).

        Example — messages from a specific sender in the last 7 days:
            from datetime import datetime, timedelta
            cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat() + "Z"
            messages = client.messages.list(
                inbox_id="i_abc",
                sender="vip@client.com",
                after=cutoff,
                order="asc",
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

        data = self._http.get("/v1/messages", params=params)
        if isinstance(data, list):
            return [Message.model_validate(m) for m in data]
        return [Message.model_validate(m) for m in (data or [])]


class _Attachments:
    """Attachment upload and retrieval — send files with agent emails.

    Attachments are uploaded separately from the email send, then referenced
    by ID. This two-step pattern lets you re-use the same attachment across
    multiple emails without re-uploading.

    Typical workflow:
        1. Upload the file: upload = client.attachments.upload(content, filename, mime_type)
        2. Send email with attachment: client.messages.send(..., attachments=[upload.attachment_id])
        3. Retrieve a download URL: client.attachments.url(attachment_id)

    Example::

        import base64

        # Upload a file
        with open("invoice.pdf", "rb") as f:
            content = base64.b64encode(f.read()).decode()

        upload = client.attachments.upload(
            content=content,
            filename="invoice.pdf",
            mime_type="application/pdf",
        )

        # Use in an email
        client.messages.send(
            to="user@example.com",
            subject="Invoice",
            html="<p>See attached.</p>",
            attachments=[upload.attachment_id],
        )

        # Get download URL (e.g. to display in a UI)
        url_info = client.attachments.url(upload.attachment_id)
        print(url_info.url)  # → https://... (expires in 1 hour by default)
    """

    def __init__(self, http: HttpClient):
        self._http = http

    def upload(
        self,
        content: str,
        filename: str,
        mime_type: str,
    ) -> AttachmentUpload:
        """Upload a file attachment for use in outbound emails.

        Upload the file once, then pass the returned attachment_id to
        messages.send() in the attachments list. The attachment is stored
        securely and can be referenced in multiple emails.

        Args:
            content: Base64-encoded file content. Encode in Python with:
                     base64.b64encode(file_bytes).decode("utf-8")
            filename: Original filename shown to the recipient
                      (e.g. "Q4_Report.pdf", "invoice_1234.xlsx").
            mime_type: MIME type of the file.
                Common values:
                  "application/pdf"      — PDF documents
                  "image/png"            — PNG images
                  "image/jpeg"           — JPEG images
                  "text/csv"             — CSV spreadsheets
                  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                         — Excel (.xlsx)

        Returns:
            AttachmentUpload with:
              .attachment_id — pass this to messages.send(attachments=[...])
              .filename      — echoed back for confirmation
              .size          — file size in bytes

        Example — attach a generated PDF report:
            import base64
            from reportlab.pdfgen import canvas
            import io

            buf = io.BytesIO()
            c = canvas.Canvas(buf)
            c.drawString(100, 750, "Monthly Report")
            c.save()

            upload = client.attachments.upload(
                content=base64.b64encode(buf.getvalue()).decode(),
                filename="monthly_report.pdf",
                mime_type="application/pdf",
            )

            client.messages.send(
                to="manager@company.com",
                subject="Monthly Report",
                text="Please find the report attached.",
                inbox_id=inbox.id,
                attachments=[upload.attachment_id],
            )

        Example — attach a CSV export:
            import csv, io, base64
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerows(data_rows)
            csv_bytes = buf.getvalue().encode("utf-8")

            upload = client.attachments.upload(
                content=base64.b64encode(csv_bytes).decode(),
                filename="export.csv",
                mime_type="text/csv",
            )
        """
        payload = UploadAttachmentPayload(
            content=content,
            filename=filename,
            mime_type=mime_type,
        )
        data = self._http.post(
            "/v1/attachments/upload",
            json=payload.model_dump(exclude_none=True),
        )
        return AttachmentUpload.model_validate(data)

    def get(self, attachment_id: str) -> Attachment:
        """Get metadata for an attachment received in an inbound email.

        Use this when processing inbound emails that contain attachments.
        The attachment IDs are available on Message.attachments (a list of IDs).
        Call this to get the filename, MIME type, and size before deciding
        whether to download it. Then call .url() to get a download link.

        Args:
            attachment_id: The attachment ID from Message.attachments list.

        Returns:
            Attachment with:
              .attachment_id — same as the input
              .filename      — original filename (e.g. "receipt.pdf")
              .mime_type     — content type (e.g. "application/pdf")
              .size          — file size in bytes

        Example — process attachments from an inbound email:
            messages = client.threads.messages(thread_id)
            latest = messages[-1]
            for attachment_id in latest.attachments:
                meta = client.attachments.get(attachment_id)
                if meta.mime_type == "application/pdf" and meta.size < 10_000_000:
                    url_info = client.attachments.url(attachment_id)
                    # Download and process the PDF
                    pdf_bytes = requests.get(url_info.url).content
                    extracted_text = pdf_to_text(pdf_bytes)
        """
        data = self._http.get(f"/v1/attachments/{quote(attachment_id)}")
        return Attachment.model_validate(data)

    def url(self, attachment_id: str, *, expires_in: int = 3600) -> AttachmentUrl:
        """Get a temporary signed download URL for an attachment.

        Use this to download attachment content — either to process inbound
        attachments (e.g. extract data from a PDF) or to share a download link
        with a user. URLs expire after the specified time.

        Args:
            attachment_id: The attachment ID from Message.attachments or
                           AttachmentUpload.attachment_id.
            expires_in: URL expiration time in seconds (default 3600 = 1 hour).
                        Increase for links you plan to share with users.
                        Maximum is typically 86400 (24 hours).

        Returns:
            AttachmentUrl with:
              .url       — presigned download URL (GET to download the file)
              .filename  — original filename
              .mime_type — content type
              .expires_in — how long until the URL expires (seconds)

        Example — download and process an inbound attachment:
            import requests
            url_info = client.attachments.url(attachment_id)
            response = requests.get(url_info.url)
            content = response.content  # raw bytes

        Example — long-lived link for user download:
            url_info = client.attachments.url(attachment_id, expires_in=86400)
            return {"download_url": url_info.url, "filename": url_info.filename}
        """
        data = self._http.get(
            f"/v1/attachments/{quote(attachment_id)}/url",
            params={"expires_in": expires_in},
        )
        return AttachmentUrl.model_validate(data)


class _Search:
    """Full-text search across email threads.

    Use client.search.threads() to find conversations by subject or content.
    Returns ranked thread summaries — call threads.messages() on each result
    to load full conversation history.

    Example::

        results = client.search.threads(
            query="invoice",
            inbox_id="i_abc123",
            limit=10,
        )
        for r in results:
            print(r.thread_id, r.subject, r.snippet)
    """

    def __init__(self, http: HttpClient):
        self._http = http

    def threads(
        self,
        query: str,
        *,
        inbox_id: str | None = None,
        domain_id: str | None = None,
        limit: int = 20,
    ) -> list[SearchResult]:
        """Search across email threads by subject or content.

        Returns ranked thread summaries. Provide at least one of inbox_id or
        domain_id to scope the search. Use threads.messages() on each result
        to load the full conversation before generating a reply.

        Args:
            query: Search query string. Searches subject lines and message body
                   content. Supports natural language (e.g. "invoice from January",
                   "meeting rescheduled", "password reset request").
            inbox_id: Scope search to a single inbox (recommended). Returns
                      only threads in this inbox.
            domain_id: Scope search to a domain. Returns threads from all
                       inboxes under the domain.
            limit: Max results to return (1–100, default 20).

        Returns:
            List of SearchResult objects ordered by relevance. Each has
            .thread_id, .subject, .snippet, and .message_count.

        Example — find threads matching a topic:
            results = client.search.threads(
                query="refund request",
                inbox_id=support_inbox_id,
            )
            for r in results:
                messages = client.threads.messages(r.thread_id)
                context = format_for_llm(messages)
                reply = agent.generate_reply(context)
        """
        params: dict[str, Any] = {"q": query, "limit": limit}
        if inbox_id:
            params["inbox_id"] = inbox_id
        if domain_id:
            params["domain_id"] = domain_id
        data = self._http.get("/v1/search/threads", params=params)
        if isinstance(data, list):
            return [SearchResult.model_validate(r) for r in data]
        return [SearchResult.model_validate(r) for r in (data or [])]


class _Delivery:
    """Deliverability monitoring — track email delivery health and manage suppressions.

    Use client.delivery.metrics() to get delivery statistics (sent, delivered,
    bounced, complained) for an inbox or domain. Use .suppressions() to audit
    addresses that have been automatically blocked.

    Example::

        metrics = client.delivery.metrics(inbox_id="i_abc123", period="7d")
        print(f"Delivery rate: {metrics.delivery_rate:.1f}%")
        print(f"Bounce rate: {metrics.bounce_rate:.1f}%")
    """

    def __init__(self, http: HttpClient):
        self._http = http

    def metrics(
        self,
        *,
        inbox_id: str | None = None,
        domain_id: str | None = None,
        period: str = "7d",
    ) -> DeliveryMetrics:
        """Get email deliverability metrics for an inbox or domain.

        Returns aggregate statistics for the requested time period. Monitor
        these to catch deliverability problems early — a rising bounce rate
        or complaint rate signals sender reputation damage.

        Args:
            inbox_id: Filter metrics to a specific inbox (recommended).
            domain_id: Filter metrics to a domain (all inboxes combined).
            period: Time window — "24h", "7d" (default), or "30d".

        Returns:
            DeliveryMetrics with:
              .sent, .delivered, .bounced, .complained, .failed — raw counts
              .delivery_rate, .bounce_rate, .complaint_rate — percentages (0–100)
              .period — the period you requested

        Example — health check before a bulk send:
            metrics = client.delivery.metrics(inbox_id=outreach_inbox_id, period="7d")
            if metrics.bounce_rate and metrics.bounce_rate > 5.0:
                raise RuntimeError(
                    f"Bounce rate too high ({metrics.bounce_rate:.1f}%) — "
                    f"clean your list before sending."
                )
        """
        params: dict[str, Any] = {"period": period}
        if inbox_id:
            params["inbox_id"] = inbox_id
        if domain_id:
            params["domain_id"] = domain_id
        data = self._http.get("/v1/delivery/metrics", params=params)
        return DeliveryMetrics.model_validate(data)

    def suppressions(
        self,
        *,
        inbox_id: str | None = None,
        domain_id: str | None = None,
        limit: int = 50,
    ) -> list[DeliverySuppression]:
        """List suppressed email addresses (bounces, complaints, unsubscribes).

        Suppressed addresses are automatically skipped when you call messages.send().
        This endpoint lets you audit the list — useful for debugging why a specific
        recipient isn't receiving emails.

        Args:
            inbox_id: Filter suppressions to a specific inbox.
            domain_id: Filter suppressions to a domain.
            limit: Max results (default 50).

        Returns:
            List of DeliverySuppression objects, each with:
              .email          — suppressed address
              .reason         — "hard_bounce", "complaint", or "unsubscribe"
              .suppressed_at  — ISO 8601 timestamp
        """
        params: dict[str, Any] = {"limit": limit}
        if inbox_id:
            params["inbox_id"] = inbox_id
        if domain_id:
            params["domain_id"] = domain_id
        data = self._http.get("/v1/delivery/suppressions", params=params)
        if isinstance(data, list):
            return [DeliverySuppression.model_validate(s) for s in data]
        return [DeliverySuppression.model_validate(s) for s in (data or [])]

    def events(
        self,
        *,
        message_id: str | None = None,
        inbox_id: str | None = None,
        domain_id: str | None = None,
        event_type: str | None = None,
        limit: int = 50,
    ) -> list[DeliveryEvent]:
        """Get the delivery event log for messages.

        Track the full lifecycle of individual emails — from sent to delivered,
        or through the failure path (bounced, complained, failed). Filter by
        message_id to trace a specific email end-to-end.

        Args:
            message_id: Filter events for a specific message send.
            inbox_id: Filter events for all messages from an inbox.
            domain_id: Filter events for all messages from a domain.
            event_type: Filter by event type:
                        "sent" — accepted by Commune and handed to SMTP
                        "delivered" — confirmed received by destination server
                        "bounced" — rejected by destination server
                        "complained" — marked as spam by recipient
                        "failed" — failed before reaching SMTP
            limit: Max results (default 50).

        Returns:
            List of DeliveryEvent objects, each with .event_type, .recipient,
            .timestamp, and .detail (bounce reason or error message).
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
        data = self._http.get("/v1/delivery/events", params=params)
        if isinstance(data, list):
            return [DeliveryEvent.model_validate(e) for e in data]
        return [DeliveryEvent.model_validate(e) for e in (data or [])]


class CommuneClient:
    """Commune SDK client — email and messaging infrastructure for AI agents.

    CommuneClient is the main entry point for all Commune operations. Initialize
    it once at application startup and reuse across requests. It is thread-safe.

    Use this when you want your AI agent to:
    - Have a real email address:           client.inboxes.create()
    - Send email from that address:        client.messages.send()
    - Reply within a conversation:         client.messages.send(thread_id=...)
    - Browse conversation history:         client.threads.list(), client.threads.messages()
    - Search email content:                client.search.threads(query)
    - Monitor delivery health:             client.delivery.metrics(inbox_id)
    - Handle file attachments:             client.attachments.upload(), .get(), .url()
    - Manage sending domains:              client.domains.list(), .create(), .verify()

    Credentials:
        Pass api_key directly or set the COMMUNE_API_KEY environment variable.
        API keys begin with "comm_". Get yours at https://app.commune.email.

    Args:
        api_key: Your Commune API key (starts with "comm_").
                 Reads from COMMUNE_API_KEY env var if not passed directly.
                 Raises ValueError immediately if no key is found.
        base_url: Override the API base URL. Used for self-hosted deployments
                  or testing against a staging environment.
                  Default: https://api.commune.email
        timeout: Request timeout in seconds (default 30). Increase for slow
                 network conditions or large attachment uploads.

    Raises:
        ValueError: If no API key is provided and COMMUNE_API_KEY is not set.

    Example — basic setup:
        from commune import CommuneClient

        client = CommuneClient(api_key="comm_...")
        inbox = client.inboxes.create(local_part="support")
        print(inbox.address)  # → support@agents.commune.email

    Example — environment variable (recommended for production):
        # In shell: export COMMUNE_API_KEY=comm_...
        client = CommuneClient()  # reads from env

    Example — context manager (auto-closes HTTP connection):
        with CommuneClient(api_key="comm_...") as client:
            client.messages.send(
                to="user@example.com",
                subject="Hello",
                text="Message from your agent",
                inbox_id="i_abc123",
            )

    Example — LangChain tool integration:
        from langchain.tools import tool

        @tool
        def send_email(to: str, subject: str, body: str) -> str:
            "Send an email to a customer"
            result = client.messages.send(
                to=to, subject=subject, text=body, inbox_id=INBOX_ID
            )
            return f"Sent: {result.message_id}"

    Example — full webhook reply flow:
        # 1. Create inbox with webhook
        inbox = client.inboxes.create(
            local_part="support",
            webhook={"endpoint": "https://myapp.com/webhook"},
        )

        # 2. In webhook handler (FastAPI example):
        @app.post("/webhook")
        async def handle_email(request: Request):
            body = await request.body()
            verify_signature(body, request.headers["x-commune-signature"],
                             WEBHOOK_SECRET, request.headers["x-commune-timestamp"])
            payload = json.loads(body)

            reply = agent.generate_reply(payload["text"])
            client.messages.send(
                to=payload["sender"],
                subject="Re: " + payload["subject"],
                text=reply,
                inbox_id=payload["inboxId"],
                thread_id=payload["thread_id"],
            )
            return {"ok": True}
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
        self._http = HttpClient(api_key=resolved_key, base_url=base_url, timeout=timeout)
        self.domains = _Domains(self._http)
        self.inboxes = _Inboxes(self._http)
        self.threads = _Threads(self._http)
        self.messages = _Messages(self._http)
        self.attachments = _Attachments(self._http)
        self.search = _Search(self._http)
        self.delivery = _Delivery(self._http)

    def close(self) -> None:
        """Close the underlying HTTP connection pool.

        Call this when you're done with the client and not using it as a
        context manager. In long-running servers, closing the client on
        shutdown prevents connection leaks.

        Example:
            client = CommuneClient(api_key="comm_...")
            try:
                # ... use client ...
            finally:
                client.close()
        """
        self._http.close()

    def __enter__(self) -> CommuneClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
