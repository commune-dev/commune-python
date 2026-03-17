"""Typed request/response contracts for the Commune Python SDK.

This module defines the data models returned by all SDK methods. When you
call client.inboxes.create(), client.threads.list(), etc., you get instances
of these classes back — not raw dicts.

Key classes for agent developers:
    Inbox         — a dedicated email address for your agent
    Thread        — a conversation (group of related messages)
    Message       — a single email in a thread
    SendMessageResult — confirmation that your send() succeeded
    AttachmentUpload  — the ID to pass after uploading a file
"""

from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


# ── Enums / Literals ─────────────────────────────────────────────────────────

Channel = Literal["email"]
Direction = Literal["inbound", "outbound"]
ParticipantRole = Literal["sender", "to", "cc", "bcc", "mentioned", "participant"]


# ── Shared Base Model ────────────────────────────────────────────────────────


class ContractModel(BaseModel):
    """Base model with stable core fields and forward-compatible extras.

    All SDK response objects inherit from this. It allows accessing fields
    via attribute access (model.field) or dict-style access (model["field"])
    for backward compatibility with code that treats SDK responses as mappings.

    Extra fields returned by the API (not yet defined here) are stored and
    accessible via model.model_extra or dict-style access, so SDK upgrades
    that add new API fields won't break existing code.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    # Dict-like helpers for backward compatibility with code that treats SDK
    # responses as mappings.
    def __getitem__(self, key: str) -> Any:
        data = self.model_dump()
        if key not in data:
            raise KeyError(key)
        return data[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.model_dump().get(key, default)

    def items(self):
        return self.model_dump().items()

    def keys(self):
        return self.model_dump().keys()

    def values(self):
        return self.model_dump().values()


# ── Core Models ──────────────────────────────────────────────────────────────


class Participant(ContractModel):
    """A participant in an email message (sender, recipient, CC, BCC).

    Participants appear in Message.participants. Iterate over them to find
    the sender or to build a reply-to list.

    Attributes:
        role: The participant's role in the message.
              "sender"      — the From address (who sent the email)
              "to"          — direct recipient
              "cc"          — carbon copy recipient
              "bcc"         — blind carbon copy recipient
              "participant" — catch-all for other roles
        identity: The email address string (e.g. "alice@example.com").
    """

    role: ParticipantRole
    identity: str


class MessageMetadata(ContractModel):
    """Extended metadata attached to every message.

    This is the place to look for structured extraction results, spam
    information, and low-level email headers. Most agent workflows only
    need .extracted_data (if you set an extraction_schema on the inbox)
    and .delivery_status for outbound messages.

    Attributes:
        created_at: ISO 8601 timestamp when the message was received/sent.
        subject: Email subject line.
        in_reply_to: Message-ID this message replies to (used for threading).
        references: List of Message-IDs in the thread chain.
        inbox_id: The inbox this message belongs to.
        inbox_address: The inbox's email address.
        message_id: SMTP Message-ID for delivery tracking.
        extracted_data: Structured data auto-parsed from the email body if
            the inbox has an extraction_schema configured. Use this to skip
            manual parsing of structured inbound emails.
        spam_score: Spam probability score (0.0–1.0). Higher = more likely spam.
        spam_flagged: True if the message was flagged as spam.
        delivery_status: Delivery state for outbound messages.
            "queued", "sent", "delivered", "bounced", "failed"
        prompt_injection_detected: True if a prompt injection attack was
            detected in the email body. Check this before passing inbound
            email content to an LLM.
        prompt_injection_risk: Risk level — "low", "medium", "high".
        prompt_injection_score: Numerical confidence score for injection detection.
    """

    created_at: str
    subject: Optional[str] = None
    in_reply_to: Optional[str] = None
    references: Optional[List[str]] = None
    is_private: Optional[bool] = None
    domain_id: Optional[str] = None
    inbox_id: Optional[str] = None
    inbox_address: Optional[str] = None
    message_id: Optional[str] = None
    provider: Optional[str] = None
    extracted_data: Optional[Dict[str, Any]] = None
    spam_score: Optional[float] = None
    spam_action: Optional[str] = None
    spam_flagged: Optional[bool] = None
    delivery_status: Optional[str] = None
    prompt_injection_checked: Optional[bool] = None
    prompt_injection_detected: Optional[bool] = None
    prompt_injection_risk: Optional[str] = None
    prompt_injection_score: Optional[float] = None
    prompt_injection_signals: Optional[str] = None


class Message(ContractModel):
    """A single email message within a thread.

    Messages are the atomic unit of email. Each belongs to a Thread.
    Retrieve messages via client.threads.messages(thread_id) to get the
    full conversation history before generating an agent reply.

    Attributes:
        id: Internal message document ID.
        channel: Always "email" for this SDK.
        message_id: SMTP Message-ID (e.g. "<abc123@mail.example.com>").
            Store this if you need to track delivery or correlate with
            your email provider's logs.
        thread_id: The thread this message belongs to. Pass this back to
            client.messages.send(thread_id=...) to reply in the same thread.
            This is the most important field for agent reply workflows.
        direction: "inbound" (received from a customer) or "outbound"
            (sent by your agent). Use this to distinguish customer messages
            from agent replies when reconstructing conversation history for LLMs.
        participants: List of Participant objects — sender, To, CC, BCC.
            Filter by role="sender" to find who sent the message.
        content: Plain-text email body. Feed this to your LLM.
        content_html: HTML email body. Use for rendering in UIs.
        attachments: List of attachment IDs. Pass each to
            client.attachments.get() for metadata or client.attachments.url()
            to download.
        created_at: ISO 8601 timestamp when the message was received.
        metadata: Extended metadata including extracted_data, spam scores,
            and prompt injection detection results.

    Example — extract sender and content from an inbound message:
        messages = client.threads.messages(thread_id)
        latest = messages[-1]
        sender = next(
            p.identity for p in latest.participants if p.role == "sender"
        )
        customer_text = latest.content
        # Check for prompt injection before passing to LLM
        if latest.metadata.prompt_injection_detected:
            return "Message flagged — human review required"
        reply = llm.generate(customer_text)
    """

    id: Optional[str] = Field(None, alias="_id")
    channel: Channel = "email"
    message_id: str
    thread_id: str
    direction: Direction
    participants: List[Participant] = Field(default_factory=list)
    content: str = ""
    content_html: Optional[str] = None
    attachments: List[str] = Field(default_factory=list)
    created_at: str = ""
    metadata: MessageMetadata


# ── Threads ──────────────────────────────────────────────────────────────────


class Thread(ContractModel):
    """A thread (conversation) summary — a group of related email messages.

    Threads are returned by client.threads.list(). Each Thread is a summary
    of a conversation: it tells you the subject, when the last message arrived,
    and who the last direction was from — enough to decide whether your agent
    needs to respond, without loading all messages.

    When your agent needs to reply, call client.threads.messages(thread.thread_id)
    to get the full conversation history, then client.messages.send(..., thread_id=thread.thread_id).

    Attributes:
        thread_id: Unique conversation identifier. This is the key value —
            pass it to threads.messages() to load the conversation, and to
            messages.send(thread_id=...) to reply within it.
        subject: Email subject line for the conversation.
        last_message_at: ISO 8601 timestamp of the most recent message.
            Use for sorting or to check if a thread needs follow-up.
        first_message_at: ISO 8601 timestamp when the conversation started.
        message_count: Total number of messages in the thread (inbound + outbound).
        snippet: Preview of the most recent message body (truncated).
            Useful for displaying a thread list in a UI without loading messages.
        last_direction: "inbound" (customer sent last) or "outbound" (agent sent last).
            A thread with last_direction="inbound" typically needs an agent response.
        inbox_id: The inbox this thread lives in. Use to route replies through
            the correct inbox with messages.send(inbox_id=...).
        domain_id: The domain of the inbox.
        has_attachments: True if any message in the thread has attachments.

    Example — find threads awaiting agent response:
        result = client.threads.list(inbox_id=SUPPORT_INBOX_ID)
        needs_reply = [
            t for t in result.data
            if t.last_direction == "inbound"
        ]
        for thread in needs_reply:
            messages = client.threads.messages(thread.thread_id)
            reply = agent.generate(messages)
            client.messages.send(
                to=get_customer_email(messages),
                text=reply,
                inbox_id=thread.inbox_id,
                thread_id=thread.thread_id,
            )
    """

    thread_id: str
    subject: Optional[str] = None
    last_message_at: str
    first_message_at: Optional[str] = None
    message_count: int = 0
    snippet: Optional[str] = None
    last_direction: Optional[Direction] = None
    inbox_id: Optional[str] = None
    domain_id: Optional[str] = None
    has_attachments: bool = False


class ThreadList(ContractModel):
    """Paginated list of threads from client.threads.list().

    Use .has_more and .next_cursor to paginate through all results.

    Attributes:
        data: List of Thread summaries for this page.
        next_cursor: Opaque pagination token. Pass as cursor= in the next
            threads.list() call to get the next page. None if this is the last page.
        has_more: True if more threads exist beyond this page. Use this as the
            loop condition when paginating.

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

    data: List[Thread] = Field(default_factory=list)
    next_cursor: Optional[str] = None
    has_more: bool = False


# ── Domains ──────────────────────────────────────────────────────────────────


class InboxWebhook(ContractModel):
    """Webhook configuration attached to an inbox.

    Contains the delivery endpoint and the signing secret used to verify
    incoming webhook requests. Store .secret securely (environment variable)
    and pass it to webhooks.verify_signature() in your handler.

    Attributes:
        endpoint: The HTTPS URL Commune POSTs to when email arrives.
        events: List of subscribed event types (e.g. ["inbound"]).
        secret: HMAC-SHA256 signing secret. Pass as the `secret` argument to
            commune.webhooks.verify_signature(). Treat this like a password —
            store in an environment variable, never in code.
    """

    endpoint: Optional[str] = None
    events: Optional[List[str]] = None
    secret: Optional[str] = None


class Inbox(ContractModel):
    """A dedicated email inbox for an AI agent.

    An Inbox is a real, deliverable email address owned by your agent.
    Provision one with client.inboxes.create(). Store inbox.id in your
    database — you'll need it for messages.send() calls and webhook routing.

    Attributes:
        id: Unique identifier (e.g. "i_abc123"). Pass this as inbox_id in
            messages.send(), threads.list(), and other API calls.
        local_part: The part before @ (e.g. "support" from "support@domain.com").
        address: The full email address (e.g. "support@agents.commune.email").
            This is what customers see as the "From" address and what you give
            them to email your agent.
        display_name: Optional human-readable name shown in email clients
            alongside the address (e.g. "Acme Support Team").
        webhook: Webhook configuration — endpoint URL and signing secret.
            If set, Commune POSTs inbound email events here in real time.
            Use webhook.secret with webhooks.verify_signature().
        extraction_schema: JSON schema for auto-parsing inbound email bodies.
            When set, every inbound email's content is parsed against this schema.
            The result appears as .metadata.extracted_data on incoming Message objects,
            letting you skip manual NLP for structured inputs.
        status: "active" (receiving email) or "inactive" (delivery paused).
        domain_id: The domain this inbox belongs to.
        domain_name: The domain's name string (e.g. "agents.commune.email").

    Example — provision and store an inbox per user:
        inbox = client.inboxes.create(
            local_part=f"agent-{user.id}",
            name=f"Agent for {user.name}",
            webhook={"endpoint": "https://myapp.com/webhook"},
        )
        db.users.update(user.id, {
            "inbox_id": inbox.id,
            "inbox_address": inbox.address,
            "webhook_secret": inbox.webhook.secret,
        })
    """

    id: str
    local_part: str = Field("", alias="localPart")
    address: Optional[str] = None
    display_name: Optional[str] = Field(None, alias="displayName")
    agent: Optional[Dict[str, Any]] = None
    webhook: Optional[Union[InboxWebhook, str]] = None
    extraction_schema: Optional[Dict[str, Any]] = Field(None, alias="extractionSchema")
    created_at: Optional[str] = Field(None, alias="createdAt")
    status: Optional[str] = None
    domain_id: Optional[str] = None
    domain_name: Optional[str] = None


class DomainWebhook(ContractModel):
    """Webhook configuration for a domain (applies to all inboxes in the domain).

    Attributes:
        id: Webhook configuration ID.
        endpoint: The HTTPS URL to receive events.
        events: Subscribed event types.
        secret: Signing secret for verifying webhook requests.
    """

    id: Optional[str] = None
    endpoint: Optional[str] = None
    events: Optional[List[str]] = None
    secret: Optional[str] = None


class DomainDnsRecord(ContractModel):
    """A DNS record required to verify and activate a custom sending domain.

    Add all required records at your DNS registrar, then call
    client.domains.verify() to trigger verification.

    Attributes:
        record: Record description (e.g. "DKIM", "SPF", "MX").
        type: DNS record type — "TXT", "MX", "CNAME".
        name: The hostname to configure at your registrar
              (e.g. "_dkim._domainkey.yourdomain.com").
        value: The record value to set.
        status: "verified" (DNS is correctly set) or "pending" (not yet detected).
        ttl: Recommended TTL for the record.
        priority: Priority value for MX records.
    """

    record: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    value: Optional[str] = None
    status: Optional[str] = None
    ttl: Optional[Union[str, int]] = None
    priority: Optional[int] = None


class Domain(ContractModel):
    """A custom sending domain registered with Commune.

    Domains must be verified (DNS configured and checked) before inboxes
    under them can send or receive email.

    Attributes:
        id: Unique domain identifier (e.g. "d_abc123"). Pass as domain_id
            in inboxes.create(), inboxes.list(), and other calls.
        name: The domain string (e.g. "yourcompany.com").
        status: Verification status — "verified" (ready to use),
                "pending" (DNS not yet propagated), "failed" (DNS check failed).
        region: Deployment region for this domain.
        records: DNS records to configure at your registrar. Each record has
                 a .status showing whether it was detected correctly.
        inboxes: Inboxes under this domain (may be None if not populated).
    """

    id: str
    name: Optional[str] = None
    status: Optional[str] = None
    region: Optional[str] = None
    records: Optional[List[DomainDnsRecord]] = None
    created_at: Optional[str] = Field(None, alias="createdAt")
    inboxes: Optional[List[Inbox]] = None


# ── Attachments ──────────────────────────────────────────────────────────────


class Attachment(ContractModel):
    """Metadata for a file attachment on an email message.

    Returned by client.attachments.get(). Use this to inspect an attachment
    before downloading — check mime_type and size to decide if you want to
    process it.

    Attributes:
        attachment_id: Unique attachment identifier. Pass to attachments.url()
            to get a download URL.
        message_id: SMTP Message-ID of the email this attachment belongs to.
        filename: Original filename (e.g. "invoice.pdf", "photo.jpg").
        mime_type: Content type (e.g. "application/pdf", "image/jpeg").
        size: File size in bytes. Check this before downloading to avoid
              processing unexpectedly large files.
        source: Where the attachment was stored ("s3", "local", etc.).
        storage_type: Storage backend identifier.
    """

    attachment_id: str
    message_id: Optional[str] = None
    filename: str
    mime_type: str
    size: int
    source: Optional[str] = None
    storage_type: Optional[str] = None


class AttachmentUpload(ContractModel):
    """Response from uploading an attachment via client.attachments.upload().

    After uploading, pass .attachment_id to messages.send(attachments=[...])
    to include the file in an outbound email.

    Attributes:
        attachment_id: The ID to pass to messages.send(attachments=[attachment_id]).
            Save this if you plan to reuse the attachment in multiple emails.
        filename: The filename you provided, echoed back.
        mime_type: The MIME type you provided, echoed back.
        size: File size in bytes (confirmed after upload).
        storage_type: Storage backend used (informational).

    Example:
        upload = client.attachments.upload(
            content=base64.b64encode(pdf_bytes).decode(),
            filename="invoice.pdf",
            mime_type="application/pdf",
        )
        # Later, use in email:
        client.messages.send(
            to="customer@example.com",
            subject="Your invoice",
            text="Please find your invoice attached.",
            inbox_id=inbox.id,
            attachments=[upload.attachment_id],
        )
    """

    attachment_id: str
    filename: str
    mime_type: str
    size: int
    storage_type: Optional[str] = None


class AttachmentUrl(ContractModel):
    """A temporary signed download URL for an attachment.

    Returned by client.attachments.url(). The URL expires after .expires_in seconds.
    Use it immediately to download the file — do not store the URL long-term.

    Attributes:
        url: Presigned download URL. Make a GET request to this URL to download
             the file. No authentication required — the URL itself is the credential.
        expires_in: How many seconds until the URL expires. Default is 3600 (1 hour).
        filename: Original filename (for display or saving to disk).
        mime_type: Content type (for setting Content-Type if serving the file).
        size: File size in bytes.

    Example:
        url_info = client.attachments.url(attachment_id, expires_in=3600)
        response = requests.get(url_info.url)
        with open(url_info.filename, "wb") as f:
            f.write(response.content)
    """

    url: str
    expires_in: int = Field(0, alias="expiresIn")
    filename: str
    mime_type: str = Field("", alias="mimeType")
    size: int = 0


# ── Payloads ─────────────────────────────────────────────────────────────────


class SendMessagePayload(ContractModel):
    """Internal payload for sending an email. Use client.messages.send() instead."""

    to: Union[str, List[str]]
    subject: str
    html: Optional[str] = None
    text: Optional[str] = None
    cc: Optional[List[str]] = None
    bcc: Optional[List[str]] = None
    reply_to: Optional[Union[str, List[str]]] = None
    thread_id: Optional[str] = None
    domain_id: Optional[str] = Field(None, alias="domainId")
    inbox_id: Optional[str] = Field(None, alias="inboxId")
    attachments: Optional[List[str]] = None
    headers: Optional[Dict[str, str]] = None
    from_address: Optional[str] = Field(None, alias="from")


class CreateDomainPayload(ContractModel):
    """Internal payload for creating a domain. Use client.domains.create() instead."""

    name: str
    region: Optional[str] = None


class CreateInboxPayload(ContractModel):
    """Internal payload for creating an inbox. Use client.inboxes.create() instead."""

    local_part: str
    domain_id: Optional[str] = None
    name: Optional[str] = None
    webhook: Optional[Dict[str, Any]] = None


class UpdateInboxPayload(ContractModel):
    """Internal payload for updating an inbox. Use client.inboxes.update() instead."""

    local_part: Optional[str] = None
    webhook: Optional[Dict[str, Any]] = None
    status: Optional[str] = None


class SetInboxWebhookPayload(ContractModel):
    """Internal payload for setting a webhook. Use client.inboxes.set_webhook() instead."""

    endpoint: str
    events: Optional[List[str]] = None


class UploadAttachmentPayload(ContractModel):
    """Internal payload for uploading attachments. Use client.attachments.upload() instead."""

    content: str
    filename: str
    mime_type: str


# ── Structured Responses ─────────────────────────────────────────────────────


class DomainVerificationResult(ContractModel):
    """Result from client.domains.verify().

    Attributes:
        id: The domain ID that was verified.
        status: Verification result — "verified" (DNS is correct and active)
                or "pending" (DNS records not yet detected).
    """

    id: Optional[str] = None
    status: Optional[str] = None


class SendMessageResult(ContractModel):
    """Confirmation returned after client.messages.send() succeeds.

    Attributes:
        id: Internal message document ID.
        message_id: SMTP Message-ID assigned to the sent email. Use this to
            correlate with delivery events or your email provider's logs.
        thread_id: The thread the sent message was added to. Especially useful
            when you did NOT pass thread_id to send() — save this value if you
            want to reply in the same thread later.
        status: Delivery status — "queued" (accepted, not yet sent),
                "sent" (handed off to SMTP). Delivery confirmation comes
                via webhook ("delivery" event) when available.

    Example:
        result = client.messages.send(
            to="customer@example.com",
            subject="Welcome",
            text="Hello!",
            inbox_id=inbox.id,
        )
        # Save the thread_id for future replies
        db.save_thread(customer_id=customer.id, thread_id=result.thread_id)
    """

    id: Optional[str] = None
    message_id: Optional[str] = None
    thread_id: Optional[str] = None
    status: Optional[str] = None


class DeleteResult(ContractModel):
    """Typed common delete response."""

    ok: bool = False


# ── Search ────────────────────────────────────────────────────────────────────


class SearchResult(ContractModel):
    """A thread matching a search query (from client.search.threads()).

    Attributes:
        thread_id: Thread identifier — pass to threads.messages() to load the
                   full conversation.
        subject: Email subject of the thread.
        snippet: Short preview of the most recent message body.
        message_count: Number of messages in the thread.
        last_activity: ISO 8601 timestamp of the most recent message.
    """

    thread_id: Optional[str] = None
    subject: Optional[str] = None
    snippet: Optional[str] = None
    message_count: Optional[int] = None
    last_activity: Optional[str] = None


# ── Delivery ──────────────────────────────────────────────────────────────────


class DeliveryMetrics(ContractModel):
    """Deliverability statistics for an inbox or domain (from delivery.metrics()).

    Attributes:
        sent: Total emails sent in the period.
        delivered: Emails confirmed delivered by the receiving server.
        bounced: Emails that bounced (hard or soft).
        complained: Emails that triggered spam complaints.
        failed: Emails that failed to send (server errors, invalid addresses).
        delivery_rate: Delivered / sent as a percentage (0–100).
        bounce_rate: Bounced / sent as a percentage (0–100).
        complaint_rate: Complained / sent as a percentage (0–100).
        period: The time window requested (e.g. "7d", "30d").
    """

    sent: Optional[int] = None
    delivered: Optional[int] = None
    bounced: Optional[int] = None
    complained: Optional[int] = None
    failed: Optional[int] = None
    delivery_rate: Optional[float] = None
    bounce_rate: Optional[float] = None
    complaint_rate: Optional[float] = None
    period: Optional[str] = None


class DeliverySuppression(ContractModel):
    """A suppressed address — will not receive emails (from delivery.suppressions()).

    Addresses are added to the suppression list automatically when an email
    hard-bounces or triggers a spam complaint. Suppressed addresses are
    silently skipped when you call messages.send().

    Attributes:
        email: The suppressed email address.
        reason: Why the address was suppressed:
                "hard_bounce" — address does not exist or server rejected permanently.
                "complaint"   — recipient marked the email as spam.
                "unsubscribe" — recipient clicked unsubscribe.
        suppressed_at: ISO 8601 timestamp when the suppression was created.
    """

    email: Optional[str] = None
    reason: Optional[str] = None
    suppressed_at: Optional[str] = None


class DeliveryEvent(ContractModel):
    """A single delivery lifecycle event (from delivery.events()).

    Each email send generates a series of events as it moves through the
    delivery pipeline: sent → delivered (or bounced/complained/failed).

    Attributes:
        event_id: Unique ID for this event.
        message_id: The message this event belongs to.
        event_type: One of: "sent", "delivered", "bounced", "complained", "failed".
        recipient: The email address this event applies to.
        timestamp: ISO 8601 timestamp of the event.
        detail: Additional context (bounce reason, complaint type, error message).
    """

    event_id: Optional[str] = None
    message_id: Optional[str] = None
    event_type: Optional[str] = None
    recipient: Optional[str] = None
    timestamp: Optional[str] = None
    detail: Optional[str] = None
