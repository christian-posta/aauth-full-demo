---
layout: default
title: Clarification Chat During Authorization
---

In the previous flows, a pending authorization request either completed immediately or waited for user interaction. This flow covers an additional capability in [Agent Auth](https://github.com/dickhardt/AAuth): **clarification chat**. When the auth server needs more context before the user consents, it can include a clarification question in the pending response, and the agent can answer by POSTing back to the pending URL.

[← Back to index](index.md)

## Why Clarification Matters

Sometimes a user or policy engine needs more than a scope string to make a decision. A user may reasonably ask:

- Why do you need access to my calendar?
- Is this for one task or ongoing access?
- What data will actually be read?

Instead of abandoning the request or forcing the user to guess, AAuth lets the auth server ask the agent for clarification during the same deferred authorization flow.

## The Flow

### Step 1: Agent Requests the Resource

The flow begins the same way as the direct authorization and user-consent flows:

```bash
================================================================================
>>> AGENT REQUEST to https://important.resource.com/data-auth
================================================================================
GET https://important.resource.com/data-auth HTTP/1.1
Signature: sig=:7VG_a7RvQZtUD1ZdD2NrzdKeaeb4lEFu08rnT9j66aALZ78bdcoQPsIw-_0EUHmVMsSBjn527j_3DSKa4tQdAA:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1774980186
Signature-Key: sig=(scheme=jwks_uri id="https://agent.supply-chain.com" kid="key-1")
================================================================================
```

The resource responds with the usual authorization challenge:

```bash
================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 401
aauth: require=auth-token; resource-token="eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoic...
content-length: 22

[Body (22 bytes)]
Authorization required
================================================================================
```

### Step 2: Agent Requests Authorization

The agent sends the resource token to the auth server:

```bash
================================================================================
>>> AGENT TOKEN REQUEST to https://auth-server.com/token
================================================================================
POST https://auth-server.com/token HTTP/1.1
Content-Type: application/json
Signature: sig=:62f95Sue653N7Sviyj5e9rDeLZLAEl_ORZkaIVtTDi8dfASRejBGD3EVUrljXLajgi-K8jcvXmKKl0zhzQevBQ:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1774980186
Signature-Key: sig=(scheme=jwks_uri id="https://agent.supply-chain.com" kid="key-1")

[Body (537 bytes)]
{"resource_token": "eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoicmVzb3VyY2Urand0In0..."}
================================================================================
```

The auth server does not issue a token immediately. It returns a deferred response:

```bash
================================================================================
<<< AUTH SERVER RESPONSE
================================================================================
HTTP/1.1 202 Accepted
Location: https://auth-server.com/pending/a39818a6cb59
AAuth: require=interaction; code="201252Z6"
Content-Type: application/json

[Body]
{
  "status": "pending",
  "location": "https://auth-server.com/pending/a39818a6cb59",
  "require": "interaction",
  "code": "201252Z6"
}
================================================================================
```

At this point the flow looks like the earlier user-consent case, but now the pending URL can carry more information.

## Clarification During Polling

### Step 3: Pending Response Includes a Clarification Question

When the agent polls the pending URL, the pending response can include a clarification prompt from the auth server.

For this flow, the auth server asks:

```text
Why do you need access to my calendar?
```

That means the authorization request is still pending, but the auth server wants extra context from the agent before the user completes the interaction.

### Step 4: Agent POSTs `clarification_response`

The agent answers by POSTing to the same pending URL:

```bash
INFO:     127.0.0.1:55390 - "POST /pending/a39818a6cb59 HTTP/1.1" 202 Accepted
```

For this flow, the stored clarification history shows the answer that was sent:

```json
[
  {
    "response": "This agent only requests access to fulfill the current task and uses the minimum required scope.",
    "timestamp": 1774980186
  }
]
```

That round trip is the key new behavior in this flow:

- the auth server asks a question while the request is pending
- the agent answers on the same pending resource
- the overall authorization flow stays in one continuous protocol exchange

## User Consent Continues Normally

### Step 5: User Completes Interaction

After clarification, the user still completes the normal interaction flow:

```bash
INFO:     127.0.0.1:55391 - "GET /interact?code=201252Z6 HTTP/1.1" 200 OK
INFO:     127.0.0.1:55391 - "POST /interact HTTP/1.1" 303 See Other
INFO:     127.0.0.1:55391 - "GET /interact?code=201252Z6 HTTP/1.1" 200 OK
INFO:     127.0.0.1:55391 - "POST /interact HTTP/1.1" 200 OK
```

Once consent is complete, the pending URL returns the final auth token.

### Step 6: Agent Polls and Retries the Resource

The agent receives the completed authorization result:

```bash
INFO:     127.0.0.1:55392 - "GET /pending/a39818a6cb59 HTTP/1.1" 200 OK
```

It then retries the original resource request with `scheme=jwt`:

```bash
================================================================================
>>> AGENT REQUEST to https://important.resource.com/data-auth
================================================================================
GET https://important.resource.com/data-auth HTTP/1.1
Signature: sig=:f0mjg1Th9epSxyXFA20fgkYMFAX3yLV5jYZTfnQGT0y1EtSG6bWQEFg1fiqCBuBbjLtvzJQkUDXGvfFfx5-zCw:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1774980188
Signature-Key: sig=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3M...")
================================================================================
```

The resource grants access:

```bash
================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 200
content-length: 212
content-type: application/json

[Body (212 bytes)]
{"message":"Access granted","data":"This is protected data (authorized)","scheme":"jwt","token_type":"auth+jwt","method":"GET","agent":"https://agent.supply-chain.com","agent_delegate":null,"scope":"data.read data.write"}
================================================================================
```

## When Clarification Is Not Supported

Clarification chat is optional. For this flow, there is also a second case where the agent does **not** support clarification. In that case, the auth server does not enable clarification for the pending request.

That matters because clarification should only be used when:

- the agent has indicated it supports it
- the auth server has a question worth asking
- the deployment is willing to treat the agent’s answer as untrusted input that still needs policy and UI handling

## Why This Matters

Clarification chat gives AAuth a way to handle ambiguous or high-context requests without inventing a separate side channel.

It allows:

- richer user decisions
- more informed consent
- policy systems that can ask for extra context
- one continuous deferred flow instead of bolting on custom chat plumbing

And it still preserves the same core structure:

- signed requests
- deferred responses with a pending URL
- user interaction when required
- proof-of-possession auth tokens at the end

## Summary

Clarification chat extends the pending authorization flow by allowing the auth server to ask the agent for more context before consent completes. The agent polls the pending URL, receives a clarification question, POSTs a `clarification_response` back to that same pending URL, and then continues through the normal user-interaction and token-delivery steps. This keeps the exchange inside the AAuth flow instead of pushing it into an out-of-band channel.

## Where to Next

We've now covered:

- [Pseudonymous (HWK)](./flow-01-hwk.md): Cryptographic proof without identity
- [Identified (JWKS)](./flow-02-jwks.md): Domain-bound agent identity
- [Authorized (Direct)](./flow-03-authz.md): Runtime authorization without user interaction
- [User Consent](./flow-04-user.md): Interactive authorization with user approval
- [Token Exchange](./flow-05-token-ex.md): Multi-hop downstream authorization
- [Agent Delegation](./flow-06-delegated.md): Distributed agent identity
- **Clarification Chat (this post)**: Asking the agent for more context during authorization

[← Back to index](index.md)
