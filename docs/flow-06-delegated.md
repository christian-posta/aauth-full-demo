---
layout: default
title: Agent Delegation - Distributing Identity Across Workloads and Devices
description: How agent tokens enable distributed identity without shared keys
---

In [previous posts](./flow-05-token-ex.md), we explored direct authorization, user consent, token exchange, and other ways agents and resources obtain access. This flow covers a different problem: how one logical agent can safely operate through multiple delegates, each with its own signing key. This is where [Agent Auth](https://github.com/dickhardt/AAuth) uses **agent delegation** and **agent tokens**.

[← Back to index](index.md)

## The Distributed Identity Problem

Modern agents rarely run as a single process with a single key. Consider:

- a personal assistant with laptop, phone, and tablet installations
- a microservice deployed in many containers
- a background worker fleet spread across zones
- a CLI and a hosted service that both act as the same product

Each instance needs to act as the same logical agent, but naive approaches break down:

1. Shared signing keys create one large blast radius.
2. Separate agent identifiers fragment policy and user understanding.
3. Bearer-style delegation loses proof-of-possession.

AAuth’s delegation model takes a different approach:

- one stable parent agent identity
- many delegates, each with its own keypair
- short-lived `agent+jwt` tokens binding each delegate key to the parent identity

## Roles in This Flow

This flow uses two agent-side roles:

- **Agent server**: the authoritative identity holder
  - publishes metadata and JWKS
  - issues agent tokens to delegates
  - represents the parent agent identity

- **Agent delegate**: a specific execution instance
  - generates its own signing key
  - requests an agent token from the agent server
  - signs requests with its own key
  - presents the agent token to prove it is acting under the parent agent identity

## The Flow

![](./images/demo6.png)

### Phase 1: The Delegate Obtains an Agent Token

The delegate first asks the agent server for an agent token:

```bash
================================================================================
>>> DELEGATE REQUEST to https://agent.supply-chain.com/delegate/token
================================================================================
POST https://agent.supply-chain.com/delegate/token HTTP/1.1
Content-Type: application/json

[Body (143 bytes)]
{"sub": "delegate-1", "cnf_jwk": {"kty": "OKP", "crv": "Ed25519", "x": "-XbMHZc393RgM8I3PFQqLYWLnOSC1KPCA1hYgOyAxVc", "kid": "delegate-key-1"}}
================================================================================
```

The delegate sends:

- `sub`: a stable delegate identifier
- `cnf_jwk`: the delegate’s public key

In a real deployment, this request would not be anonymous. The delegate still needs to authenticate to the agent server before the agent server will issue an agent token. AAuth leaves that authentication method out of scope so deployments can use whatever attestation or platform identity fits their environment. Common examples include:

- server workloads using mTLS, SPIFFE, or cloud workload identity
- mobile apps using platform attestation
- desktop or CLI clients using user login, device credentials, or enterprise identity

So the important distinction is:

- AAuth defines the agent token that comes out of this step
- the deployment defines how the delegate proves it is entitled to ask for that token

The agent server responds with an agent token:

```bash
================================================================================
<<< AGENT SERVER RESPONSE
================================================================================
HTTP/1.1 200 OK
Content-Type: application/json

[Body]
{
  "agent_token": "eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiYWdlbnQrand0In0...",
  "expires_in": 3600
}
================================================================================
```

### The Agent Token Shape

For this flow, the agent token looks like this:

```json
{
  "alg": "EdDSA",
  "kid": "key-1",
  "typ": "agent+jwt"
}
```

```json
{
  "iss": "https://agent.supply-chain.com",
  "sub": "delegate-1",
  "jti": "8eb1e0fc-db74-4446-909d-664052a379c6",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "-XbMHZc393RgM8I3PFQqLYWLnOSC1KPCA1hYgOyAxVc",
      "kid": "delegate-key-1"
    }
  },
  "iat": 1774977290,
  "exp": 1774980890
}
```

The important parts are:

- `typ: agent+jwt` identifies this as an agent token
- `iss` is the parent agent identity
- `sub` is the delegate identifier
- `cnf.jwk` binds the token to the delegate’s key

This means the delegate can say: “I am delegate `delegate-1`, acting for `https://agent.supply-chain.com`, and this is the specific key I’m allowed to use.”

## Phase 2: The Delegate Accesses a Resource

With the agent token, the delegate can now call a resource that requires agent identity:

```bash
================================================================================
>>> DELEGATE REQUEST to https://important.resource.com/data-jwks
================================================================================
GET https://important.resource.com/data-jwks HTTP/1.1
Signature: sig=:ooGVsioU9vOZplVZgQFjCACPyIMQg9iLf7qFms-Owq4_4PAidGMS5bsG-Z2yMl2EdShZRfaaOAESypP1ABNxBg:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1774977290
Signature-Key: sig=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiYWdlbnQrand0In0.eyJpc3MiOiJo...")
================================================================================
```

The delegate signs the request with its own private key. The resource verifies:

1. the `agent+jwt` signature using the parent agent server’s JWKS
2. the token’s claims (`iss`, `sub`, `exp`, `typ`)
3. the request signature using the key inside `cnf.jwk`
4. that the request signature matches the key bound in the agent token

If all of that checks out, the resource grants access:

```bash
================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 200
content-length: 206
content-type: application/json

[Body (206 bytes)]
{"message":"Access granted","data":"This is protected data (identified via agent token)","scheme":"jwt","token_type":"agent+jwt","method":"GET","agent":"https://agent.supply-chain.com","agent_delegate":"delegate-1"}
================================================================================
```

Notice what the resource learns:

- `agent`: the parent agent identity
- `agent_delegate`: the specific delegate instance

That gives the resource both a stable policy identity and per-delegate visibility for auditing or rate limiting.

## Phase 3: Delegates and Auth Tokens

Delegation also matters when a resource requires authorization, not just identity. In that case, the delegate follows the same auth-token flow as any other caller, but presents the `agent+jwt` instead of proving identity via JWKS discovery.

Conceptually, that request looks like:

```bash
================================================================================
>>> DELEGATE REQUEST to https://auth-server.com/token
================================================================================
POST https://auth-server.com/token HTTP/1.1
Content-Type: application/json
Signature-Key: sig=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiYWdlbnQrand0In0...")

[Body]
{"resource_token":"..."}
================================================================================
```

The auth server can then:

1. validate the agent token against the parent agent’s JWKS
2. validate the resource token
3. verify the request signature against `cnf.jwk`
4. issue an auth token that records both the parent agent and the delegate

That resulting auth token would include claims like:

```json
{
  "iss": "https://auth-server.com",
  "aud": "https://important.resource.com",
  "agent": "https://agent.supply-chain.com",
  "agent_delegate": "delegate-1",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "-XbMHZc393RgM8I3PFQqLYWLnOSC1KPCA1hYgOyAxVc",
      "kid": "delegate-key-1"
    }
  },
  "scope": "data.read data.write"
}
```

That `agent_delegate` claim tells the resource exactly which delegate was responsible for the authorization.

For this flow, we focus on two concrete things:

- obtaining and validating the `agent+jwt`
- using that `agent+jwt` successfully against a resource that requires identity

It then notes that the same delegated identity can be used in the auth-token flow as well.

## Why Delegation Matters

This solves a real operational problem for distributed agents:

- each delegate gets its own keypair
- the parent identity remains stable
- compromised delegates can be revoked independently
- key rotation does not require inventing a brand-new agent identity
- resources and auth servers can still attribute behavior to a specific delegate

That gives you a clean balance:

- one logical agent identity for policy and user understanding
- many delegate keys for operational safety and flexibility

## Summary

Agent delegation lets multiple workloads or devices act as one logical agent without sharing a signing key. The parent agent server issues short-lived `agent+jwt` tokens to delegates, each bound to the delegate’s own key. Resources can then verify both the parent agent identity and the delegate instance that made the request. This preserves proof-of-possession, supports per-delegate auditing and policy, and avoids the security problems of shared keys.

## Where to Next

We've now covered:

- [Pseudonymous (HWK)](./flow-01-hwk.md): Cryptographic proof without identity
- [Identified (JWKS)](./flow-02-jwks.md): Domain-bound agent identity
- [Authorized (Direct)](./flow-03-authz.md): Runtime authorization without user interaction
- [User Consent](./flow-04-user.md): Interactive authorization with user approval
- [Token Exchange](./flow-05-token-ex.md): Multi-hop authorization chains
- **Agent Delegation (this post)**: Distributing identity across workloads and devices

After these flows, we have the main building blocks for putting AAuth into a real implementation.

[In the next post](./flow-07-clarification.md), we look at clarification chat, where the auth server can ask the agent for additional context during a pending authorization flow.

[← Back to index](./index.md)
