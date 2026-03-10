[![PyPI](https://img.shields.io/pypi/v/commune-mail?color=blue&label=PyPI)](https://pypi.org/project/commune-mail/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/commune-mail?label=downloads%2Fmo&color=blue)](https://pypi.org/project/commune-mail/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://pypi.org/project/commune-mail/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-commune.email-blue)](https://commune.email/docs?ref=commune-python)
[![MCP Server](https://img.shields.io/badge/MCP-commune--mcp-purple)](https://github.com/shanjai-raj/commune-mcp)
[![Cookbook](https://img.shields.io/badge/examples-commune--cookbook-green)](https://github.com/shanjai-raj/commune-cookbook)

# commune-mail

Give your Python agent a real inbox. Send email, receive webhooks, manage threads — in 4 lines.

```bash
pip install commune-mail
```

```python
from commune import CommuneClient

client = CommuneClient(api_key="comm_...")  # or set COMMUNE_API_KEY env var

# Create a dedicated inbox for your agent — no domain setup, no DNS
inbox = client.inboxes.create(local_part="support")
print(inbox.address)  # → "support@agents.commune.email"

# Send email from the inbox
client.messages.send(
    to="user@example.com",
    subject="Your ticket has been received",
    text="Thanks for reaching out. We'll respond within 2 hours.",
    inbox_id=inbox.id,
)

# Reply within an existing thread (keeps conversation grouped in email client)
client.messages.send(
    to="user@example.com",
    subject="Re: Your ticket",
    text="Issue resolved — here's what we did...",
    inbox_id=inbox.id,
    thread_id=thread_id,  # from webhook payload
)
```

---

## What you can build

- **Customer support agents** — Receive inbound tickets at `support@yourcompany.com`, classify intent with an LLM, route to the right handler, and reply in the same thread. The customer sees a normal email conversation.
- **Hiring pipelines** — Outreach sequences to candidates, automated screening replies, interview scheduling, offer letters — all tracked per thread per candidate.
- **Sales automation** — Personalized cold email from a CRM, follow-up sequences, lead qualification over email, handoff to human when warm.
- **Investor updates** — Scheduled portfolio reports, deal flow notifications, LP communications — all with proper threading and read receipts.
- **Multi-agent coordination** — Agents hand off tasks to each other via email. Agent A delegates to Agent B by sending to `researcher@org.commune.email`. Agent B processes and replies in the same thread. No shared database — the thread IS the task context. Full audit trail preserved permanently.
- **Agent identity** — Every agent gets a permanent email address. `client.inboxes.create(local_part="my-agent")` returns `my-agent@org.commune.email` — a stable identity that survives process restarts, framework changes, and infrastructure migrations. See [agent-to-agent examples →](https://github.com/shanjai-raj/commune-cookbook/tree/main/agent-to-agent)

---

## Why commune-mail instead of alternatives

| | Commune | Gmail API | SendGrid | Resend | Raw SMTP |
|---|---|---|---|---|---|
| Per-agent isolated inbox | ✅ | ❌ shared inbox | ❌ | ❌ | ❌ |
| Inbound email + webhooks | ✅ | ✅ (complex setup) | ❌ | ✅ (limited) | ❌ |
| Outbound sending | ✅ | ✅ | ✅ | ✅ | ✅ |
| Email threading (RFC 5322) | ✅ automatic | ✅ manual | ❌ | ❌ | ❌ manual |
| Semantic search across history | ✅ | ❌ | ❌ | ❌ | ❌ |
| Structured JSON extraction | ✅ per-inbox schemas | ❌ | ❌ | ❌ | ❌ |
| Prompt injection protection | ✅ built-in | ❌ | ❌ | ❌ | ❌ |
| Agent-native design | ✅ | ❌ (human-first) | ❌ | ❌ | ❌ |
| Self-hostable | ✅ | ❌ | ❌ | ❌ | ✅ |

**The key difference:** Gmail API, SendGrid, and Resend are designed for humans or for bulk email. Commune is designed specifically for AI agents — each agent gets its own inbox, inbound emails fire webhooks, threads maintain conversation context, and the platform handles prompt injection and spam so your agent doesn't have to.

---

## How it works

```
Inbound:  User email → Commune → webhook → Your agent → [LLM reasoning] → reply via Commune → User email client
                                                ↓
                                    thread history / semantic search
                                    structured extraction
                                    prompt injection check

Outbound: Your agent → commune.messages.send() → Commune → SMTP → User email client
                                                      ↓
                                            DKIM/SPF signed
                                            delivery tracking
                                            bounce handling
```

## Concepts

Commune organizes email around four layers:

```
Domain  →  Inbox  →  Thread  →  Message
```

- **Domain** — A custom email domain you own (e.g. `example.com`). You verify it by adding DNS records.
- **Inbox** — A mailbox under a domain (e.g. `support@example.com`). Each inbox can have webhooks for real-time notifications.
- **Thread** — A conversation: a group of related email messages sharing a subject/reply chain. Identified by `thread_id`.
- **Message** — A single email (inbound or outbound) within a thread.

---

## Quickstart

From zero to a working email agent in 4 lines — no domain setup, no DNS:

```python
from commune import CommuneClient

client = CommuneClient(api_key="comm_...")

# Create an inbox — domain is auto-assigned
inbox = client.inboxes.create(local_part="support")
print(f"Inbox ready: {inbox.address}")  # → "support@agents.commune.email"

# List email threads
threads = client.threads.list(inbox_id=inbox.id, limit=5)
for t in threads.data:
    print(f"  [{t.message_count} msgs] {t.subject}")

# Send an email (use inbox.id from the create step)
client.messages.send(
    to="user@example.com",
    subject="Hello from my agent",
    text="Hi there!",
    inbox_id=inbox.id,
)
```

That's it. No domain verification, no DNS records. Just create an inbox and start sending/receiving.

## Async support

Every method is available as `async`/`await` via `AsyncCommuneClient`:

```python
import asyncio
from commune import AsyncCommuneClient

async def main():
    async with AsyncCommuneClient(api_key="comm_...") as client:
        inbox = await client.inboxes.create(local_part="support")
        print(f"Inbox ready: {inbox.address}")

        await client.messages.send(
            to="user@example.com",
            subject="Hello from async",
            text="Sent with asyncio!",
            inbox_id=inbox.id,
        )

asyncio.run(main())
```

The async client has the exact same API surface — just `await` every call.

## Client

```python
from commune import CommuneClient

client = CommuneClient(
    api_key="comm_...",     # Or set COMMUNE_API_KEY env var.
    base_url=None,          # Optional. Override API URL.
    timeout=30.0,           # Optional. Request timeout in seconds.
)
```

The API key can be passed directly or read from the `COMMUNE_API_KEY` environment variable:

```bash
export COMMUNE_API_KEY="comm_..."
```

```python
# No api_key needed — reads from environment
client = CommuneClient()
```

Supports context manager:

```python
with CommuneClient(api_key="comm_...") as client:
    domains = client.domains.list()
# Connection closed automatically
```

---

## Domains

Domains are the foundation. You register a domain, add DNS records, verify it, then create inboxes under it.

### `client.domains.list()`

List all domains in your organization.

```python
domains = client.domains.list()
# → [Domain(id="d_abc123", name="example.com", status="verified", ...)]
```

**Returns:** `list[Domain]`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Domain ID |
| `name` | `str` | Domain name |
| `status` | `str` | `"not_started"`, `"pending"`, `"verified"`, `"failed"` |
| `region` | `str` | AWS region |
| `records` | `list` | DNS records (MX, TXT, CNAME) |
| `inboxes` | `list[Inbox]` | Inboxes under this domain |

### `client.domains.create(name, region=None)`

Register a new domain. After creating, you'll need to verify it.

```python
domain = client.domains.create(name="example.com")
print(domain.id)      # → "d_abc123"
print(domain.status)  # → "not_started"
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | `str` | Yes | Domain name (e.g. `"example.com"`) |
| `region` | `str` | No | AWS region (e.g. `"us-east-1"`) |

### `client.domains.get(domain_id)`

Get full details for a single domain.

```python
domain = client.domains.get("d_abc123")
```

### `client.domains.records(domain_id)`

Get the DNS records you need to add at your registrar.

```python
records = client.domains.records("d_abc123")
for r in records:
    print(f"  {r['type']} {r['name']} → {r['value']}")
```

**Returns:** `list[dict]` — each record has `type`, `name`, `value`, `status`, `ttl`.

### `client.domains.verify(domain_id)`

Trigger verification after you've added the DNS records.

```python
result = client.domains.verify("d_abc123")
```

### Typical flow

```python
# 1. Create the domain
domain = client.domains.create(name="example.com")

# 2. Get DNS records to configure
records = client.domains.records(domain.id)
print("Add these DNS records at your registrar:")
for r in records:
    print(f"  {r['type']} {r['name']} → {r['value']}")

# 3. After adding records, verify
result = client.domains.verify(domain.id)

# 4. Check status
domain = client.domains.get(domain.id)
print(f"Status: {domain.status}")  # → "verified"
```

---

## Inboxes

Inboxes are mailboxes that receive and send email. Create one with just a `local_part` — the domain is auto-assigned.

### `client.inboxes.create(local_part, *, domain_id=None, name=None, webhook=None)`

Create a new inbox. Domain is **auto-resolved** if not provided — no DNS setup needed.

```python
# Simplest — domain auto-assigned
inbox = client.inboxes.create(local_part="support")
print(inbox.address)  # → "support@agents.commune.email"

# Explicit domain (if you have a custom domain)
inbox = client.inboxes.create(local_part="billing", domain_id="d_abc123")
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `local_part` | `str` | Yes | Part before `@` (e.g. `"support"`, `"billing"`) |
| `domain_id` | `str` | No | Domain to create under. Auto-resolved if omitted. |
| `name` | `str` | No | Display name |
| `webhook` | `dict` | No | `{"endpoint": "https://...", "events": ["inbound"]}` |

**Returns:** `Inbox`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Inbox ID |
| `local_part` | `str` | Part before `@` |
| `address` | `str` | Full email address |
| `webhook` | `InboxWebhook \| str \| None` | Webhook configuration |
| `status` | `str \| None` | Inbox status |
| `created_at` | `str \| None` | ISO timestamp |

### `client.inboxes.list(domain_id=None)`

List inboxes. Without `domain_id`, lists all inboxes across all domains.

```python
# All inboxes
inboxes = client.inboxes.list()

# Inboxes for a specific domain
inboxes = client.inboxes.list(domain_id="d_abc123")
```

### `client.inboxes.get(domain_id, inbox_id)`

```python
inbox = client.inboxes.get("d_abc123", "i_xyz")
```

### `client.inboxes.update(domain_id, inbox_id, **fields)`

Update one or more fields. Only provided fields are changed.

```python
inbox = client.inboxes.update("d_abc123", "i_xyz", local_part="help")
```

### `client.inboxes.set_webhook(domain_id, inbox_id, *, endpoint, events=None)`

Shortcut to set a webhook. You'll receive a POST when emails arrive.

```python
client.inboxes.set_webhook(
    "d_abc123", "i_xyz",
    endpoint="https://your-app.com/webhook",
    events=["inbound"],
)
```

### `client.inboxes.remove(domain_id, inbox_id)`

Delete an inbox permanently.

```python
client.inboxes.remove("d_abc123", "i_xyz")  # → True
```

---

## Threads

A thread is a conversation — a group of related email messages. Threads are listed with **cursor-based pagination** for efficient browsing of large mailboxes.

### `client.threads.list(*, inbox_id=None, domain_id=None, limit=20, cursor=None, order="desc")`

List threads for an inbox or domain. Returns newest first by default.

```python
result = client.threads.list(inbox_id="i_xyz", limit=10)

for thread in result.data:
    print(f"[{thread.message_count} msgs] {thread.subject}")
    print(f"  Last activity: {thread.last_message_at}")
    print(f"  Preview: {thread.snippet}")

# Paginate
if result.has_more:
    page2 = client.threads.list(inbox_id="i_xyz", cursor=result.next_cursor)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `inbox_id` | `str` | One of these | Filter by inbox |
| `domain_id` | `str` | required | Filter by domain |
| `limit` | `int` | No | 1–100, default 20 |
| `cursor` | `str` | No | Cursor from previous `next_cursor` |
| `order` | `str` | No | `"desc"` (newest first) or `"asc"` |

**Returns:** `ThreadList`

```python
ThreadList(
    data=[Thread(...)],   # List of thread summaries
    next_cursor="abc...", # Pass to next call for next page (None if no more)
    has_more=True,        # Whether more pages exist
)
```

**Thread object:**

| Field | Type | Description |
|-------|------|-------------|
| `thread_id` | `str` | Thread identifier |
| `subject` | `str \| None` | Email subject |
| `last_message_at` | `str` | ISO timestamp of last message |
| `first_message_at` | `str \| None` | ISO timestamp of first message |
| `message_count` | `int` | Total messages in thread |
| `snippet` | `str \| None` | Preview of last message (up to 200 chars) |
| `last_direction` | `str \| None` | `"inbound"` or `"outbound"` |
| `inbox_id` | `str \| None` | Inbox this thread belongs to |
| `domain_id` | `str \| None` | Domain this thread belongs to |
| `has_attachments` | `bool` | Whether any message has attachments |

### `client.threads.messages(thread_id, *, limit=50, order="asc")`

Get all messages in a thread. Returns oldest first by default (chronological reading order).

```python
messages = client.threads.messages("thread_abc123")

for msg in messages:
    sender = next((p.identity for p in msg.participants if p.role == "sender"), "unknown")
    print(f"  [{msg.direction}] From: {sender}")
    print(f"  Subject: {msg.metadata.subject}")
    print(f"  {msg.content[:200]}")
    print()
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `thread_id` | `str` | Yes | Thread ID |
| `limit` | `int` | No | 1–1000, default 50 |
| `order` | `str` | No | `"asc"` (chronological) or `"desc"` |

**Returns:** `list[Message]`

**Message object:**

| Field | Type | Description |
|-------|------|-------------|
| `message_id` | `str` | Unique message identifier |
| `thread_id` | `str` | Thread ID this message belongs to |
| `direction` | `str` | `"inbound"` or `"outbound"` |
| `participants` | `list[Participant]` | `[{role: "sender", identity: "user@..."}, ...]` |
| `content` | `str` | Plain text body |
| `content_html` | `str \| None` | HTML body |
| `attachments` | `list[str]` | Attachment IDs |
| `created_at` | `str` | ISO timestamp |
| `metadata.subject` | `str` | Subject line |
| `metadata.inbox_id` | `str` | Inbox ID |

---

## Messages

### `client.messages.send(**kwargs)`

Send an email. Returns the sent message data.

```python
result = client.messages.send(
    to="user@example.com",
    subject="Order Confirmation",
    html="<h1>Thanks for your order!</h1><p>Your order #1234 is confirmed.</p>",
)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `to` | `str \| list[str]` | Yes | Recipient(s) |
| `subject` | `str` | Yes | Subject line |
| `html` | `str` | No* | HTML body |
| `text` | `str` | No* | Plain text body |
| `from_address` | `str` | No | Sender (uses domain default) |
| `cc` | `list[str]` | No | CC recipients |
| `bcc` | `list[str]` | No | BCC recipients |
| `reply_to` | `str` | No | Reply-to address |
| `thread_id` | `str` | No | Reply in existing thread |
| `domain_id` | `str` | No | Send from specific domain |
| `inbox_id` | `str` | No | Send from specific inbox |
| `attachments` | `list[str]` | No | Attachment IDs |
| `headers` | `dict[str, str]` | No | Custom headers |

*At least one of `html` or `text` is required.

**Reply to a thread:**

```python
client.messages.send(
    to="customer@gmail.com",
    subject="Re: Order Issue",
    html="<p>We're looking into this for you.</p>",
    thread_id="thread_abc123",  # continues the thread
    inbox_id="i_xyz",
)
```

### `client.messages.list(**kwargs)`

List messages with filters. Provide at least one of `inbox_id`, `domain_id`, or `sender`.

```python
messages = client.messages.list(
    inbox_id="i_xyz",
    limit=20,
    order="desc",
    after="2025-01-01T00:00:00Z",
)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `inbox_id` | `str` | One of | Filter by inbox |
| `domain_id` | `str` | these | Filter by domain |
| `sender` | `str` | required | Filter by sender email |
| `limit` | `int` | No | 1–1000, default 50 |
| `order` | `str` | No | `"asc"` or `"desc"` (default) |
| `before` | `str` | No | ISO date — messages before this time |
| `after` | `str` | No | ISO date — messages after this time |

---

## Attachments

Upload files, then reference them when sending emails.

### `client.attachments.upload(content, filename, mime_type)`

Upload a file. Returns an `attachment_id` you pass to `messages.send()`.

```python
import base64

with open("invoice.pdf", "rb") as f:
    content = base64.b64encode(f.read()).decode()

upload = client.attachments.upload(
    content=content,
    filename="invoice.pdf",
    mime_type="application/pdf",
)
print(upload.attachment_id)  # → "a1b2c3d4e5f67890a1b2c3d4e5f67890"
print(upload.size)           # → 45230
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `str` | Yes | Base64-encoded file data |
| `filename` | `str` | Yes | Original filename |
| `mime_type` | `str` | Yes | MIME type |

**Returns:** `AttachmentUpload`

| Field | Type | Description |
|-------|------|-------------|
| `attachment_id` | `str` | ID to use in `messages.send()` |
| `filename` | `str` | Filename |
| `mime_type` | `str` | MIME type |
| `size` | `int` | Size in bytes |

### `client.attachments.get(attachment_id)`

Get metadata for an uploaded attachment.

```python
att = client.attachments.get("a1b2c3d4...")
print(att.filename, att.mime_type, att.size)
```

### `client.attachments.url(attachment_id, *, expires_in=3600)`

Get a temporary download URL.

```python
url_info = client.attachments.url("a1b2c3d4...", expires_in=7200)
print(url_info.url)         # → "https://..."
print(url_info.expires_in)  # → 7200
```

**Returns:** `AttachmentUrl`

| Field | Type | Description |
|-------|------|-------------|
| `url` | `str` | Temporary download URL |
| `expires_in` | `int` | Seconds until URL expires |
| `filename` | `str` | Filename |
| `mime_type` | `str` | MIME type |
| `size` | `int` | Size in bytes |

### Full attachment flow

```python
import base64

# 1. Upload the file
with open("report.pdf", "rb") as f:
    content = base64.b64encode(f.read()).decode()

upload = client.attachments.upload(content, "report.pdf", "application/pdf")

# 2. Send email with attachment
client.messages.send(
    to="user@example.com",
    subject="Monthly Report",
    html="<p>Please find the report attached.</p>",
    attachments=[upload.attachment_id],
)

# 3. Later, get a download URL for that attachment
url_info = client.attachments.url(upload.attachment_id)
print(f"Download: {url_info.url}")
```

---

## Webhook Verification

Commune signs every outbound webhook delivery with HMAC-SHA256. The signature uses the format `v1={hex_digest}` and the timestamp is Unix **milliseconds**:

```
x-commune-signature: v1=5a3f2b...
x-commune-timestamp: 1707667200000
```

Always verify before processing:

```python
from commune import verify_signature, WebhookVerificationError

# In your webhook handler (Flask, FastAPI, Django, etc.)
try:
    verify_signature(
        payload=request.body,
        signature=request.headers["x-commune-signature"],
        secret="whsec_...",  # Your inbox webhook secret
        timestamp=request.headers["x-commune-timestamp"],
    )
except WebhookVerificationError as e:
    print(f"Invalid webhook: {e}")
    return 401
```

You can also compute signatures yourself (useful for testing):

```python
from commune import compute_signature

sig = compute_signature(payload=body, secret="whsec_...", timestamp="1707667200000")
# → "v1=5a3f2b..."
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `payload` | `bytes \| str` | Yes | Raw request body |
| `signature` | `str` | Yes | `x-commune-signature` header (`v1=...`) |
| `secret` | `str` | Yes | Your inbox webhook secret |
| `timestamp` | `str` | Yes* | `x-commune-timestamp` header (Unix ms) |
| `tolerance_seconds` | `int` | No | Max age in seconds (default 300) |

\* Technically optional, but the backend always sends it. Omitting it skips timestamp-based signing and freshness checks.

---

## Error Handling

All errors inherit from `CommuneError`. Catch specific types or the base class.

```python
from commune import (
    CommuneClient,
    CommuneError,
    AuthenticationError,
    NotFoundError,
    ValidationError,
    RateLimitError,
)

try:
    client = CommuneClient(api_key="comm_...")
    domain = client.domains.get("nonexistent")
except AuthenticationError:
    # 401 — invalid or expired API key
    print("Check your API key")
except NotFoundError:
    # 404 — resource doesn't exist
    print("Domain not found")
except ValidationError as e:
    # 400 — bad request parameters
    print(f"Invalid request: {e.message}")
except RateLimitError:
    # 429 — too many requests
    print("Slow down, try again in a moment")
except CommuneError as e:
    # Catch-all for any API error
    print(f"Error ({e.status_code}): {e.message}")
```

| Exception | HTTP Status | When |
|-----------|-------------|------|
| `AuthenticationError` | 401 | Invalid/expired API key |
| `PermissionDeniedError` | 403 | API key lacks required permissions |
| `ValidationError` | 400 | Bad request parameters |
| `NotFoundError` | 404 | Resource doesn't exist |
| `RateLimitError` | 429 | Too many requests |
| `CommuneError` | Any | Base class for all errors |

> **Note:** `PermissionDeniedError` is the recommended name. `PermissionError` is kept as a backward-compatible alias but shadows the Python builtin — prefer `PermissionDeniedError` in new code.

---

## Search, Triage, Delivery, and Extraction

The Python SDK now includes full `/v1` parity for these capability groups.

### Structured extraction (per inbox)

```python
client.inboxes.set_extraction_schema(
    domain_id="d_abc",
    inbox_id="inbox_xyz",
    name="support_ticket",
    schema={
        "type": "object",
        "properties": {
            "intent": {"type": "string"},
            "priority": {"type": "string"},
        },
    },
)
```

### Semantic thread search

```python
results = client.search.threads(
    "customer asking for refund",
    inbox_id="inbox_xyz",
    limit=10,
)
```

### Thread triage

```python
client.threads.set_status("thread_123", "needs_reply")
client.threads.add_tags("thread_123", ["vip", "billing"])
client.threads.assign("thread_123", "agent:alice")
```

### Delivery insights

```python
metrics = client.delivery.metrics(domain_id="d_abc", period="7d")
events = client.delivery.events(domain_id="d_abc", limit=50)
suppressions = client.delivery.suppressions(inbox_id="inbox_xyz")
```

---

## Security

Commune is built as production email infrastructure — deliverability, authentication, and abuse prevention are handled at the platform level so you don't have to build them yourself.

### Email Authentication (DKIM, SPF, DMARC)

Every custom domain you verify through Commune is configured with proper email authentication records:

- **DKIM** — All outbound emails are cryptographically signed. The signing keys are managed by Commune; you add the CNAME record to your DNS during domain setup.
- **SPF** — Sender Policy Framework records authorize Commune's mail servers to send on behalf of your domain, preventing spoofing.
- **DMARC** — Domain-based Message Authentication is configured to instruct receiving mail servers how to handle unauthenticated messages from your domain.

When you call `client.domains.records(domain_id)`, the returned DNS records include all three. Once added and verified, your domain passes authentication checks at Gmail, Outlook, and other major providers.

### Inbound Spam Protection

All inbound email is analyzed before it reaches your inbox or webhook:

- **Content analysis** — Subject and body are scored for spam patterns, phishing keywords, and suspicious formatting.
- **URL validation** — Links are checked for phishing indicators, typosquatting, and low-authority domains.
- **Sender reputation** — Each sender builds a reputation score over time. Repeat offenders are automatically blocked.
- **Domain authority** — Sender domains are checked for MX records, SPF, DMARC, valid SSL, and structural red flags.
- **DNSBL checking** — Sender IPs are checked against DNS-based blackhole lists.
- **Mass attack detection** — Burst patterns (high volume + low quality) are detected per-organization and throttled automatically.

Emails scoring above the reject threshold are silently dropped. Borderline emails are flagged with spam metadata in the message object so your agent can decide how to handle them.

### Outbound Protection

Outbound emails are validated before sending to protect your domain reputation:

- **Content scanning** — Outgoing messages are checked for spam-like patterns before delivery.
- **Recipient limits** — Maximum 50 recipients per message to prevent mass mailing.
- **Redis-backed rate limiting** — Distributed sliding-window rate limiting powered by Redis (with in-memory fallback). Accurate across multiple server instances.
- **Burst detection** — Real-time burst detection using Redis sorted sets with dual sliding windows (10-second and 60-second). Sudden spikes in send volume are automatically throttled with a `429` response.

### Attachment Scanning

All inbound attachments are scanned before storage:

- **ClamAV integration** — When a ClamAV daemon is available (via `CLAMAV_HOST`), attachments are scanned using the INSTREAM protocol over TCP.
- **Heuristic fallback** — When ClamAV is unavailable, a multi-layer heuristic scanner checks file extensions, MIME types, magic bytes, double extensions, VBA macros in Office documents, and suspicious archive files.
- **Known threat database** — File hashes (SHA-256) are stored for all detected threats. Subsequent uploads of the same file are instantly blocked.
- **Quarantine** — Dangerous attachments are quarantined (not stored) and flagged in the message metadata.

### Encryption at Rest

When `EMAIL_ENCRYPTION_KEY` is set (64 hex characters = 256 bits):

- Email body (`content`, `content_html`) and subject are encrypted with **AES-256-GCM** before storage in MongoDB.
- Attachment content stored in the database is also encrypted.
- Each encrypted value uses a unique random IV and includes a GCM authentication tag for tamper detection.
- Decryption is transparent — the API returns plaintext to authorized callers.
- Existing unencrypted data continues to work (the system detects the `enc:` prefix).

### DMARC Reporting

Commune provides end-to-end DMARC aggregate report processing:

- **Report ingestion** — Submit DMARC XML reports via `POST /v1/dmarc/reports` (supports XML, gzip, and zip formats).
- **Automatic parsing** — Reports are parsed following RFC 7489 Appendix C, extracting per-record authentication results.
- **Failure alerting** — Authentication failures above 10% trigger warnings in server logs.
- **Summary API** — `GET /v1/dmarc/summary?domain=example.com&days=30` returns pass/fail rates, DKIM/SPF breakdowns, and top sending IPs.
- **Auto-cleanup** — Reports older than 1 year are automatically removed via TTL index.

### Delivery Metrics & Bounce Handling

Bounces, complaints, and delivery events are tracked automatically:

- **Automatic suppression** — Hard bounces and spam complaints automatically add recipients to the suppression list.
- **Delivery metrics API** — `GET /v1/delivery/metrics?inbox_id=...&days=7` returns sent, delivered, bounced, complained, and failed counts with calculated rates.
- **Event stream** — `GET /v1/delivery/events?inbox_id=...` lists recent delivery events for debugging.
- **Suppression list** — `GET /v1/delivery/suppressions?inbox_id=...` shows all suppressed addresses.

### Rate Limits

| Tier | Emails/hour | Emails/day | Domains/day | Inboxes/day |
|------|-------------|------------|-------------|-------------|
| Free | 100 | 1,000 | 5 | 50 |
| Pro | 10,000 | 100,000 | 50 | 500 |
| Enterprise | Unlimited | Unlimited | Unlimited | Unlimited |

Rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`) are included in API responses. When exceeded, the API returns `429 Too Many Requests` — catch this with `RateLimitError`.

### API Key Security

- API keys use the `comm_` prefix followed by 64 cryptographically random hex characters.
- Keys are **bcrypt-hashed** before storage — the raw key is only shown once at creation.
- Each key has **granular permission scopes**: `domains:read`, `domains:write`, `inboxes:read`, `inboxes:write`, `threads:read`, `messages:read`, `messages:write`, `attachments:read`, `attachments:write`.
- Keys are scoped to a single organization and can be revoked or rotated at any time from the dashboard.
- Maximum 10 active keys per organization.

### Webhook Verification

Inbound webhook payloads from Commune are signed with your inbox webhook secret. Always verify the signature before processing:

```python
# The webhook secret is provided when you configure a webhook on an inbox.
# Verify the X-Commune-Signature and X-Commune-Timestamp headers
# before trusting the payload.
```

### Attachment Security

- Uploaded attachments are stored in secure cloud storage with per-object access control.
- Download URLs are **temporary** (default 1 hour, configurable up to 24 hours) and expire automatically.
- Attachments are scoped to the organization that uploaded them.

---

## FAQ

**How do I give my LangChain agent its own email address?**
Install `commune-mail`, create an inbox with `client.inboxes.create(local_part="myagent")`, and wrap the send/receive calls as LangChain tools. The inbox gets a real address like `myagent@agents.commune.email` — no DNS setup required. See the [commune-cookbook](https://github.com/shanjai-raj/commune-cookbook) for a complete LangChain email tool example.

**Can my agent receive emails and respond automatically?**
Yes. Set a webhook URL on the inbox using `client.inboxes.set_webhook(domain_id, inbox_id, endpoint="https://yourapp.com/webhook")`. When an email arrives, Commune POSTs the full message payload — including sender, subject, body, and `thread_id` — to your endpoint. Your agent processes it and replies with `client.messages.send(..., thread_id=thread_id)`.

**What happens if my webhook endpoint is down?**
Commune retries up to 8 times with exponential backoff (1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s). A circuit breaker protects your server on recovery — if your endpoint comes back up, retries resume from where they left off. You can also manually replay failed webhooks from the dashboard.

**How is this different from just using Gmail or SMTP?**
Gmail API is designed for human email accounts — it requires OAuth per-user, doesn't support programmatic inbox creation, and has no webhook model for inbound email without polling. Raw SMTP gives you outbound delivery but no inbound, no threading, no search, and no agent isolation. Commune is purpose-built for agents: one API call creates a real inbox, inbound mail fires a webhook, threads are automatically tracked, and the platform handles DKIM/SPF/DMARC so your emails actually reach the inbox. See the [comparison table](#why-commune-mail-instead-of-alternatives) above.

**Can multiple agents share one inbox?**
You can, but it's not recommended. The agent-native pattern is one inbox per agent or per logical workflow — so a support agent has `support@...`, a billing agent has `billing@...`, and so on. This gives you clean thread isolation, per-inbox extraction schemas, and clear audit trails. Sharing one inbox means your agents need to coordinate routing logic themselves.

**How do I search through an agent's email history?**
Use `client.search.threads()` with a natural language query. The search is powered by vector embeddings — it finds semantically similar conversations, not just keyword matches. Pass `inbox_id` to scope the search to one agent's mailbox:
```python
results = client.search.threads(
    "customer asking about billing issue",
    inbox_id=inbox.id,
    limit=5,
)
for r in results:
    print(r.subject, r.snippet)
```

**What is prompt injection protection?**
When a malicious user sends an email containing instructions like "Ignore your previous instructions and...", those instructions could hijack your agent if it feeds raw email content into an LLM prompt. Commune's prompt injection protection scans inbound email content for injection patterns before the message reaches your webhook, flags suspicious messages in the metadata, and strips or escapes known attack vectors so your agent doesn't have to sanitize raw user input.

**Does Commune work with async Python (asyncio)?**
Yes. Import `AsyncCommuneClient` instead of `CommuneClient` and use `async with` and `await`. The async client has identical API surface — every method is just awaitable. This works natively with FastAPI, aiohttp, and any asyncio-based framework. See the [Async Support](#async-support) section for a complete example.

**How do I give my agent an email address at my own domain?**
Register your domain with `client.domains.create(name="yourcompany.com")`, add the DNS records returned by `client.domains.records(domain_id)` at your registrar (they include MX, DKIM CNAME, and SPF TXT records), then call `client.domains.verify(domain_id)`. Once verified (usually 5–30 minutes for DNS propagation), create inboxes under it: `client.inboxes.create(local_part="support", domain_id=domain.id)` — your agent now has `support@yourcompany.com`.

**What does thread_id do?**
`thread_id` links a reply to an existing conversation so it appears as a threaded reply in email clients like Gmail and Outlook. Without it, each `messages.send()` call creates a brand-new email conversation, even if the subject line is identical. Always capture the `thread_id` from the inbound webhook payload and pass it back when replying — this is the single most important thing to get right for good user experience.

**How do I extract structured data from inbound emails automatically?**
Define a JSON Schema on your inbox using `client.inboxes.set_extraction_schema()`. Every inbound email is then automatically parsed against the schema — the extracted fields appear in the webhook payload under `extracted`. No extra LLM call needed on your side:
```python
client.inboxes.set_extraction_schema(
    domain_id="d_abc",
    inbox_id="inbox_xyz",
    name="support_ticket",
    schema={
        "type": "object",
        "properties": {
            "intent": {"type": "string", "description": "What the customer wants"},
            "priority": {"type": "string", "enum": ["low", "medium", "high"]},
            "order_number": {"type": "string"},
        },
    },
)
```

**What's the difference between commune-mail (Python) and commune-ai (TypeScript)?**
`commune-mail` is the Python SDK — the one this README covers. `commune-ai` (npm: `commune-ai`) is the TypeScript/JavaScript SDK with an identical API surface, designed for Node.js, Deno, Bun, and edge runtimes. Both SDKs talk to the same Commune API. Choose based on your agent's runtime — Python for LangChain/CrewAI/standard Python agents, TypeScript for Node.js agents or Vercel AI SDK workflows.

**Can I self-host Commune?**
Yes. The Commune server is open-source and can be deployed on your own infrastructure. You'll need MongoDB, Redis, and an SMTP relay (e.g. AWS SES or Postfix). Set `COMMUNE_API_KEY`, `EMAIL_ENCRYPTION_KEY`, and `CLAMAV_HOST` (optional) in your environment. The Python SDK's `base_url` parameter lets you point it at your self-hosted instance: `CommuneClient(api_key="...", base_url="https://your-commune-server.com")`.

**How do I handle attachments?**
Upload attachments first with `client.attachments.upload(content, filename, mime_type)` where `content` is base64-encoded. This returns an `attachment_id`. Pass that ID in the `attachments` list when calling `messages.send()`. To access inbound attachments, retrieve the attachment ID from the message object and call `client.attachments.url(attachment_id)` to get a temporary signed download URL (default 1-hour expiry).

**What does the API key look like?**
API keys use the `comm_` prefix followed by 64 cryptographically random lowercase hex characters — e.g. `comm_a1b2c3d4e5f6...` (68 characters total). Keys are bcrypt-hashed before storage so the raw value is only shown once at creation. Store it in an environment variable (`COMMUNE_API_KEY`) and never commit it to source control. You can create and revoke keys from the [Commune dashboard](https://commune.email).

---

## Frameworks

commune-mail works out of the box with any Python framework or agent orchestrator:

- **LangChain** — Wrap `client.messages.send()` and `client.search.threads()` as `Tool` objects; use inbox webhooks to trigger agent chains.
- **CrewAI** — Give each crew member its own dedicated inbox; agents email each other with full thread tracking.
- **OpenAI Agents SDK** — Use commune-mail in function tools exposed to the model; the agent calls `send_email` and `get_thread` as native tool calls.
- **Claude tool_use** — Define commune-mail operations as tool schemas; Claude calls them directly during reasoning.
- **MCP (Model Context Protocol)** — Use the [commune-mcp](https://github.com/shanjai-raj/commune-mcp) server to expose Commune capabilities as MCP tools to any MCP-compatible client.
- **n8n** — Use the HTTP Request node to call the Commune REST API directly, or use commune-mail in an n8n Code node.

See the [commune-cookbook](https://github.com/shanjai-raj/commune-cookbook) for complete working examples with each framework.

---

## Ecosystem

| Package | Description |
|---------|-------------|
| [commune](https://github.com/shanjai-raj/commune) | Email & SMS infrastructure — self-hostable backend |
| [commune-ai](https://github.com/shanjai-raj/commune-ai) | TypeScript/Node.js SDK |
| **[commune-python](https://github.com/shanjai-raj/commune-python)** | **Python SDK** |
| [commune-mcp](https://github.com/shanjai-raj/commune-mcp) | MCP server for Claude Desktop, Cursor, Windsurf |
| [commune-cli](https://github.com/shanjai-raj/commune-cli) | Command-line interface |

---

## Resources

- **Docs:** [commune.email/docs](https://commune.email/docs)
- **PyPI:** [pypi.org/project/commune-mail](https://pypi.org/project/commune-mail/)
- **npm (TypeScript SDK):** [npmjs.com/package/commune-ai](https://www.npmjs.com/package/commune-ai)
- **MCP Server:** [github.com/shanjai-raj/commune-mcp](https://github.com/shanjai-raj/commune-mcp)
- **Cookbook:** [github.com/shanjai-raj/commune-cookbook](https://github.com/shanjai-raj/commune-cookbook)
- **Start Here (cookbook):** [00_START_HERE.md](https://github.com/shanjai-raj/commune-cookbook/blob/main/00_START_HERE.md)
- **API Reference:** [API_REFERENCE.md](API_REFERENCE.md)

## License

Apache-2.0
