---
layout: default
title: Agent Delegation - Distributing Identity Across Workloads and Devices
description: How agent tokens enable distributed identity without shared keys
---

In [previous posts](./flow-05-token-exchange.md), we explored how resources with established identities can exchange tokens to act on behalf of agents. But what happens when a single logical agent needs to operate across multiple execution contexts: server workloads, mobile devices, desktop applications each with its own keys and identity? This post covers how [AAuth](https://github.com/dickhardt/agent-auth) enables **agent delegation** through agent tokens.

[← Back to index](index.md)

## The Distributed Identity Problem

Modern agents rarely run in a single monolithic process. Consider:

- A personal assistant with instances on laptop, phone, and tablet
- A microservice with containers across multiple availability zones
- A trading agent with regional deployments for low latency
- A mobile app with millions of unique installations

Each instance needs to prove the same agent identity, but traditional approaches create problems:

1. **Shared secrets**: All instances use the same signing key
   - Key compromise affects entire agent identity
   - No per-instance revocation
   - Difficult key rotation
   
2. **Separate identities**: Each instance gets its own agent identifier
   - Authorization policies must list every instance
   - User sees "laptop agent," "phone agent," "server agent" separately
   - Lost semantic unity of "this is the same agent"

3. **Bearer tokens**: Central service issues session tokens
   - No proof-of-possession per instance
   - Tokens can be stolen and replayed
   - Requires online token validation

AAuth's delegation model provides a fourth option: **distributed proof-of-possession identity**. Multiple delegates share one agent identity while each holding unique keys.


## How Agent Delegation Works

Agent delegation involves two roles:

- **Agent server**: The authoritative identity holder at `https://agent.supply-chain.com`
  - Publishes JWKS at `/.well-known/aauth-agent`
  - Issues agent tokens to delegates
  - Can also make signed requests directly (which is what we've seen so far in this series of posts)
  - Basically acts as a "CA"

- **Agent delegate**: An execution instance that receives an agent token
  - Server workloads (containers, serverless functions, microservices)
  - Mobile app installations (each with unique installation ID)
  - Desktop applications, CLI tools, edge devices
  - Each has its own signing key pair
  - Still needs to authenticate itself to the agent server to get an agent token

The delegation flow has three phases:

### Phase 1: Delegate Obtains Agent Token

The delegate authenticates to the agent server and receives an agent token binding its ephemeral key to the agent identity. **How the delegate authenticates is out-of-scope for the AAuth specification** - but different deployments may use different mechanisms:

- **Server workloads**: mTLS with SPIFFE certificates, cloud provider instance identity, Kubernetes service account tokens
- **Mobile apps**: Platform attestation (iOS App Attest, Android Play Integrity)
- **Desktop apps**: User login, device certificates, enterprise credentials

From our test output, we see a simple delegate token request:

```bash
================================================================================
>>> DELEGATE REQUEST to https://agent.supply-chain.com/delegate/token
================================================================================
POST https://agent.supply-chain.com/delegate/token HTTP/1.1
Content-Type: application/json

[Body]
{
  "sub": "delegate-1",
  "cnf_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "F3qaAzz4oWqJllxanygNdyR8o5apnV3uXmUQQZeT5Ys",
    "kid": "delegate-key-1"
  }
}
================================================================================
```

The delegate provides:
- **`sub`**: Delegate identifier (persists across key rotations)
- **`cnf_jwk`**: The delegate's public key

*Note: In production, this request would include authentication credentials (mTLS, bearer token, etc.) - this example flow omits this for clarity.*

The agent server issues an agent token:

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

### Agent Token Structure

The agent token is a JWT with these claims:

```json
{
  "alg": "EdDSA",
  "kid": "key-1",
  "typ": "agent+jwt"
}
{
  "iss": "https://agent.supply-chain.com",
  "sub": "delegate-1",
  "exp": 1768789821,
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "F3qaAzz4oWqJllxanygNdyR8o5apnV3uXmUQQZeT5Ys",
      "kid": "delegate-key-1"
    }
  }
}
```

Key elements:
- **Header `typ: agent+jwt`**: Identifies this as an agent token (not auth token)
- **`iss`**: The agent identity - this is what resources see as the agent
- **`sub`**: The delegate identifier - persists across key rotations
- **`cnf.jwk`**: Cryptographically binds this token to the delegate's signing key
- **Signature**: Signed by the agent server using its JWKS

The delegate now has cryptographic proof: "I am delegate-1 of agent https://agent.supply-chain.com, bound to this specific key."

### Phase 2: Delegate Accesses Resources

The delegate can now access resources using the agent token to fulfill the Signature-Key / Signature with the jwt scheme, Basically the agent signs with its epheeral key and then presents the agent token to the receiver to verify the signature. Presenting it via the `Signature-Key` header:

```bash
================================================================================
>>> DELEGATE REQUEST to https://important.resource.com/data-jwks
================================================================================
GET https://important.resource.com/data-jwks HTTP/1.1
Signature: sig1=:g1VmPaHtG7B1_vZ0FmmegnAtf804jio4EpC866wHyuPeQM07ikVZmAWxc5hjxR1SiveSq3ib9lgzDf7GwRL9AA:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786221
Signature-Key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiYWdlbnQrand0In0...")
================================================================================
```

The resource validates:

1. **Agent token signature**: Verify using the agent server's JWKS from `https://agent.supply-chain.com/.well-known/aauth-agent`
2. **Agent token claims**: Check `iss`, `typ: agent+jwt`, expiration
3. **Request signature**: Verify using the key from `cnf.jwk` in the agent token
4. **Cryptographic binding**: The request signature must match the key bound in the agent token



## Phase 3: Delegate Requests Auth Tokens

For resources requiring authorization, the delegate follows the standard [authorization flow](./flow-03-authz.md), but presents the agent token instead of JWKS-based identity:

```bash
================================================================================
>>> DELEGATE REQUEST to https://auth-server.com/agent/token
================================================================================
POST https://auth-server.com/agent/token HTTP/1.1
Content-Digest: sha-256=:rMyTWCblP3KXnWkI2KGnDVqj91ETqvcEUuzSrXChi+c=:
Content-Type: application/x-www-form-urlencoded
Signature: sig1=:ICv_zjE12EOoEOSKofQR9R3-IoRL7TM0DEc2Q8cJubwoRnbWvFNUDQQFiVizugLFeTAmBQ4JqRGv2qLpQO8GBw:
Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=...
Signature-Key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiYWdlbnQrand0In0...")

[Body]
request_type=auth&resource_token=eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoicmVzb3VyY2Urand0In0...
================================================================================
```

The auth server validates:
1. The agent token signature (from the parent agent's JWKS)
2. The resource token signature
3. The request signature matches `cnf.jwk` in the agent token
4. Policy: Is this delegate authorized to act as this agent?

If approved, the auth server issues an auth token:

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
      "x": "F3qaAzz4oWqJllxanygNdyR8o5apnV3uXmUQQZeT5Ys",
      "kid": "delegate-key-1"
    }
  },
  "scope": "data.read data.write",
  "exp": 1768789821
}
```

Note the `agent_delegate` claim—the auth token records which delegate performed the authorization. The resource can use this for audit logging, delegate-specific policies, or rate limiting.


## Key Rotation Without Breaking Refresh Tokens

One of the key benefits of agent delegation is **key rotation without affecting refresh tokens**. The `sub` claim (delegate identifier) persists while keys rotate:

**Scenario**: A container restarts (ephemeral keys are lost):

1. **Before restart**:
   - Agent token: `sub: spiffe://supply-chain.com/api`, `cnf.jwk: KEY_A`
   - Refresh token at auth server: bound to `agent: supply-chain.com` + `sub: spiffe://supply-chain.com/api`

2. **After restart**:
   - Container generates fresh key pair (KEY_B)
   - Requests new agent token from agent server
   - Agent server issues: `sub: spiffe://supply-chain.com/api`, `cnf.jwk: KEY_B` (same `sub`, new key)
   
3. **Refresh token still works**:
   - Container uses KEY_B to sign refresh request
   - Presents new agent token with KEY_B
   - Auth server validates: same `agent` + `sub`, different key is expected
   - Issues new auth token bound to KEY_B

Without delegation, key rotation would require:
- Re-authenticating the user
- Re-granting consent
- Requesting new refresh tokens
- Managing complex migration windows

With delegation, the `sub` provides stable identity while keys rotate freely.

## Summary

Agent delegation enables distributed agents while maintaining AAuth's security properties:

- **Shared identity, unique keys**: Multiple delegates act as one agent, each with its own signing key
- **Platform integration**: Leverage existing infrastructure (SPIFFE, mobile attestation, user credentials)
- **Key rotation without disruption**: `sub` provides stable identity while keys rotate
- **Per-delegate control**: Agent servers and auth servers can enforce delegate-specific policies
- **Isolation**: Compromised delegate doesn't compromise the entire agent identity
- **Proof-of-possession**: Every request cryptographically proves key ownership

The pattern recognizes that modern agents are distributed systems—containers, mobile apps, edge devices—that need to share an identity without sharing secrets. Agent tokens provide the cryptographic binding that makes this possible.

## Where to Next

We've now covered the complete AAuth authorization landscape:

- [Pseudonymous (HWK)](./flow-01-hwk.md): Cryptographic proof without identity
- [Identified (JWKS)](./flow-02-jwks.md): Domain-bound agent identity
- [Authorized (Direct)](./flow-03-authz.md): Runtime authorization without user interaction
- [User Consent](./flow-04-user.md): Interactive authorization with user approval
- [Token Exchange](./flow-05-token-ex.md): Multi-hop authorization chains
- **Agent Delegation (this post)**: Distributing identity across workloads and devices

After going through these flows, we are ready to dig into a real-life implementation with Keycloak, Agentgateway, A2A protocol, and AAuth library support. 

[← Back to index](./index.md)
