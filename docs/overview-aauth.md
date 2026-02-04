---
layout: default
title: Overview of AAuth protocol
---

# Overview of AAuth protocol

[← Back to index](index.md)

Agent Auth (AAuth -- pronounced "AY-awth") is an [exploratory spec for agent identity](https://github.com/dickhardt/agent-auth) from [Dick Hardt](https://github.com/dickhardt) who was one of the [primary authors](https://github.com/oauth-wg/oauth-v2-1/blob/main/draft-ietf-oauth-v2-1.md) of OAuth 2.1. 


My thoughts:

Scopes are known ahead of time. They are basically a contract about what a client (app) can do limited functionality can be performed within the user's permissions. 
The client is written to call specific APIs and do some specific things with the response. For example, calendar.read is only applicable for a Calendar API. The application knows that a response from the API will only have calendar events. It will then parse and do something with these events. The scope has a very noticeable boundary. The app can say "hey user, can you please approve calendar.read because I want to read the events in your calendar". On the resource server side, enforcement becomes very simple now. "does this token have this scope"?

Agents and MCP change this completely!! Agents are much more "generic client" but there is no known execution path ahead of time. Agents infer intent, dynamically decide which tools to use / chain, and determine how to use them based on their descriptions. How would they even know which scopes to request? The scopes are not known ahead of time and the client is NOT pre-registered for the scopes. 

Scopes are just the symptom of the real divergence between OAuth and AI agents:

| OAuth assumption              | Why agents break it                        |
| ----------------------------- | ------------------------------------------ |
| Client is known               | Agents are generic                         |
| Client is registered          | Agents appear dynamically                  |
| Client intent is static       | Agent intent is emergent                   |
| Scopes map to APIs            | Tools are composable and open-ended        |
| Authorization is pre-declared | Authorization must be evaluated at runtime |


OAuth intentionally moves authorization decisions "earlier in time", because it assumes future behavior can be defined up front. That break with AI Agents. For example, OAuth assumes scopes are defined ahead of time. And that the client developer reads the API documentation and knows which scopes to request. And these scopes are tied tightly to the specific API a client will call. And clients pre-register ahead of time. And the clients are "static" to the extent they code exactly what they want from an API. So when a user eventually consents to a scope (or set of scopes) a lot of trust is already baked into the model. OAuth assumes that authorization can fully happen before the actual call to an API. The target API just needs to check "was the approval granted".

AI agents come alive dynamically. Intent and behavior is NOT known ahead of time. Tool/API calls are composable and behavior emerges at runtime. It becomes very dangerous to authorize decisions "ahead of time" for AI agents (and MCP). Authorization for AI agents MUST become "is this action acceptable, at ths specific moment, given what's already happened, which derives from some authority"?  



---

## Challenge → AAuth Solution Mapping

### 1. "Nobody really knows who the client is" → HTTPS-Based Agent Identity

**The OAuth Problem:** OAuth clients are pre-registered with a `client_id` assigned by the authorization server. In dynamic ecosystems where "any agent can talk to any MCP server," this creates a registration bottleneck and doesn't give agents a *real* identity—just an opaque identifier meaningful only to one AS.

**AAuth's Solution:** Agents are identified by **HTTPS URLs** they control (e.g., `https://my-agent.example`). The agent publishes its own metadata and signing keys at a well-known endpoint:

```
https://my-agent.example/.well-known/aauth-agent
```

This means:
- No pre-registration required—the agent's identity is self-asserted and verifiable
- The identity is **portable** across any resource or auth server
- Anyone can verify the agent by fetching its published JWKS and checking signatures

From the spec's comparison table:

| Aspect | OAuth 2.1 | AAuth |
|--------|-----------|-------|
| Client Identity | Pre-registered `client_id` assigned by AS | HTTPS URL with self-published metadata |
| Registration | Required (manual or dynamic) | Optional; self-identification via HTTPS |

---

### 2. "The client was written for that server... that scope" → Discoverable Metadata & Progressive Auth

**The OAuth Problem:** Dick says OAuth assumes "you created a scope, you knew exactly what it did, and you wrote a client for that scope and that server." But agents are general-purpose—they figure out how to call APIs on the fly.

**AAuth's Solution:** Each participant (agent, resource, auth server) publishes **discoverable metadata** describing capabilities and requirements. Resources dynamically tell agents what they need via the `Agent-Auth` response header:

```http
HTTP/1.1 401 Unauthorized
Agent-Auth: httpsig; auth-token; resource="https://api.example"; scope="data.read"
```

This enables **progressive authentication**—the gradient Dick describes:

| Level | What's Required | Use Case |
|-------|-----------------|----------|
| Anonymous | Nothing | Public content |
| Pseudonymous | HTTP signature with ephemeral key (`scheme=hwk`) | Rate limit differentiation |
| Identified | Signature verified via published JWKS or agent token | Bot allowlisting |
| Authorized | Auth token from trusted AS | Protected resources |

The agent doesn't need to know in advance what's required—it discovers requirements dynamically and escalates as needed.

---

### 3. "People are conflating access tokens and ID tokens" → Unified Auth Token

**The OAuth Problem:** OAuth provides authorization (access tokens), OIDC provides authentication (ID tokens). Dick notes people "keep trying to collapse them into a single flow" but the protocols fight this.

**AAuth's Solution:** A single **auth token** type that carries both identity claims and authorization:

```json
{
  "iss": "https://auth.example",
  "aud": "https://resource.example",
  "agent": "https://my-agent.example",
  "sub": "user-123",
  "scope": "data.read data.write",
  "cnf": { "jwk": { ... } },
  "exp": 1730221200
}
```

One token, one protocol. The resource gets everything needed for access control: who's the agent (`agent`), who's the user (`sub`), what's allowed (`scope`), and proof the request is legitimate (`cnf` binding to signing key).

---

### 4. "Challenges in managing secrets and verifying client identities" → Mandatory Proof-of-Possession

**The OAuth Problem:** OAuth typically uses bearer tokens and shared client secrets. Token theft = full compromise. DPoP and mTLS exist but are optional extensions.

**AAuth's Solution:** **Every request is cryptographically signed** using HTTP Message Signatures (RFC 9421). There are no bearer tokens and no shared secrets:

| Aspect | OAuth 2.1 | AAuth |
|--------|-----------|-------|
| Token Security | Bearer tokens (DPoP optional) | Proof-of-possession only |
| Request Integrity | Optional | Mandatory via HTTPSig |
| Client Auth | Client secrets, mTLS, or none | HTTPSig on every request |

When an agent presents a token, it also signs the request with the private key bound to that token. The resource verifies the signature matches the `cnf.jwk` in the token. Stolen tokens are useless without the private key.

---

### 5. "OAuth is tightly coupled... agents are loosely coupled" → Decoupled Trust Domains

**The OAuth Problem:** In OAuth, the resource server and authorization server are typically in the same trust domain with out-of-band configuration. Dick notes this doesn't fit when "the service registers with the auth server and trusts it, even though it's in a completely different trust domain."

**AAuth's Solution:** Resources have their own cryptographic identity and issue **resource tokens** that bind authorization requests:

```json
{
  "typ": "resource+jwt",
  "iss": "https://resource.example",
  "aud": "https://auth.example", 
  "agent": "https://my-agent.example",
  "agent_jkt": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "scope": "data.read"
}
```

This enables:
- **Any resource** to work with **any auth server** without pre-registration
- **Confused deputy prevention**: The resource token binds the request to a specific agent, preventing substitution attacks
- **MITM prevention**: The auth server verifies the resource's signature, proving the request came from the legitimate resource

---

### 6. "Now you have distributed instances... managing a single long-lived secret is impractical" → Agent Delegation

**The OAuth Problem:** A single `client_id` with a shared secret doesn't work when you have thousands of distributed agent instances (containers, mobile apps, CLI tools).

**AAuth's Solution:** **Agent tokens** delegate authority from an agent server to individual agent delegates:

```
Agent Server (https://my-agent.example)
    │
    ├── issues agent token to → Instance A (ephemeral key, sub="instance-a")
    ├── issues agent token to → Instance B (ephemeral key, sub="instance-b")
    └── issues agent token to → Instance C (ephemeral key, sub="instance-c")
```

Each instance has:
- Its own **ephemeral signing key** (generated at startup, rotated frequently)
- A stable **`sub` identifier** that persists across key rotations
- Short-lived agent token binding its key to the agent's identity

Revocation is instant: don't issue new agent tokens to compromised instances. No shared secrets to rotate across a fleet.

---

### 7. "Three specs that have never been widely deployed" → Prescriptive, No Optionality

**The OAuth Problem:** Dick notes MCP requires "WWW-Authenticate header... Dynamic Client Registration... Resource Metadata" that he's "never seen in the wild." OAuth's extensibility created a fragmented ecosystem where "standards" aren't actually deployed.

**AAuth's Solution:** Binary compliance with clear requirements:

> "No optionality: Clear requirements, guaranteed interoperability"
> "Security by design: Required proof-of-possession, no optional security features that can be misconfigured"

The spec is prescriptive about what MUST be implemented. If you're AAuth-compliant, you interoperate. There's no "we implemented OAuth but not DPoP" ambiguity.

---

## Summary: The Architectural Shift

Dick's core insight is that OAuth was designed for a world where:
- Clients are **purpose-built** for specific servers
- Relationships are **pre-established** through registration
- Trust is **tightly coupled** within domains
- Security features are **optional add-ons**

AAuth is designed for a world where:
- Agents are **general-purpose** and discover capabilities dynamically
- Relationships form **on-the-fly** without registration
- Trust spans **multiple domains** with cryptographic verification
- Security is **mandatory by design**

The protocol elements—HTTPS-based identity, progressive auth levels, proof-of-possession, resource tokens, agent delegation—all flow from accepting that agents fundamentally break OAuth's assumptions rather than trying to retrofit OAuth to handle them.