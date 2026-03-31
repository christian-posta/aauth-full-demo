---
layout: default
title: Pseudonymous Bot Access
---

[Agent Auth](https://github.com/dickhardt/AAuth) supports **progressive authentication** levels: pseudonymous, identified, and authorized. This document covers the **pseudonymous** level—the lightest form of agent authentication.

[← Back to index](index.md)

## What is Pseudonymous Access?

With pseudonymous settings, an agent proves it can sign requests cryptographically without revealing a persistent identity. The resource can verify that:
- The request was signed by someone who holds the private key
- The signature is valid and the message has not been tampered with
- Requests come from the same bot over time

The agent does **not** prove a stable, verifiable identity (e.g., via a published JWKS URL). This is useful for rate limiting, abuse prevention, and progressive trust without requiring full agent registration. See things like [web-bots, website scraping, and the IETF web-bot-auth](https://datatracker.ietf.org/wg/webbotauth/about/) for more. 

## How HWK Works

The **Header Web Key (HWK)** scheme embeds the public key directly in the HTTP request header. This is the simplest signature scheme in AAuth with no key discovery, no metadata endpoints, no pre-registration required.

![](./images/demo1.png)

**Key ownership:**
- The **agent** generates and holds the private key locally
- The agent includes the **public key** inline in every request via the `Signature-Key` header
- The resource never sees or needs access to the private key

**What the resource can verify:**
1. The request was signed by someone holding the corresponding private key
2. The covered components haven't been tampered with
3. The signature was created recently (via the `created` timestamp)

**What the resource cannot verify:**
- *Who* the signer is (no identity claim)
- Whether this key belongs to a registered or known entity
- Any organizational or trust relationship


The current demo starts with an unsigned request so the resource can challenge for pseudonymous auth. The examples below use readable hostnames instead of the local demo ports:

```bash
================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data HTTP/1.1
Host: important.resource.com
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: important.resource.com
user-agent: python-httpx/0.28.1
================================================================================


================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 401
aauth: require=pseudonym
content-length: 25

[Body (25 bytes)]
Missing signature headers
================================================================================
```

The `AAuth` response header is how a resource tells an agent what it needs next. In this pseudonymous case, `require=pseudonym` means "retry with a valid HTTP message signature and header web key." In later flows, the same header can carry stronger requirements and guidance such as identified agent auth, resource and auth server information, or user interaction details. We cover several of those options in the next flows.

After that challenge, the agent retries with an HWK-signed request:

```bash
================================================================================
>>> AGENT REQUEST to https://important.resource.com/data
================================================================================
GET https://important.resource.com/data HTTP/1.1
Signature: sig=:o1zEVnjJ2NMRHQn3QT6GFMEdTCxSudDKb9OgUDXzUZ6OpMw4hjTVnbmzx_Hb_mhFdeuvORvPFhy-aqVBA50XBQ:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1774920963
Signature-Key: sig=(scheme=hwk kty="OKP" crv="Ed25519" x="gHvo19V3SU42BI4K4rhOKMfMnA9WW0qD18wdbwJm-vY")
================================================================================
```

## Understanding the Request Headers

```
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1774920963
```

This header declares *what was signed* and *how*:

| Component | Meaning |
|-----------|---------|
| `sig=` | The signature label, must match across all three headers |
| `"@method"` | The HTTP method (`GET`) is covered by the signature |
| `"@authority"` | The host (`important.resource.com`) is covered |
| `"@path"` | The path (`/data`) is covered |
| `"signature-key"` | **Critical:** The Signature-Key header itself is covered, preventing key substitution attacks |
| `created=1774920963` | Unix timestamp when the signature was created (resources typically reject signatures older than 60 seconds) |

### `Signature`
```
Signature: sig=:o1zEVnjJ2NMRHQn3QT6GFMEdTCxSudDKb9OgUDXzUZ6OpMw4hjTVnbmzx_Hb_mhFdeuvORvPFhy-aqVBA50XBQ:
```

The actual cryptographic signature, base64-encoded between colons (RFC 9421 format). 

### `Signature-Key`
```
Signature-Key: sig=(scheme=hwk kty="OKP" crv="Ed25519" x="gHvo19V3SU42BI4K4rhOKMfMnA9WW0qD18wdbwJm-vY")
```

| Parameter | Meaning |
|-----------|---------|
| `sig=` | Must match the label in `Signature-Input` and `Signature` |
| `scheme=hwk` | Header Web Key—pseudonymous, inline public key |
| `kty="OKP"` | Key type: Octet Key Pair (used for EdDSA) |
| `crv="Ed25519"` | The Ed25519 curve |
| `x="..."` | The public key value (base64url-encoded) |

**Note:** Unlike JWKs, the `alg` parameter is deliberately absent—the algorithm is inferred from the key type and signature verification context.


Resource sees:

```bash
================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data HTTP/1.1
Host: important.resource.com
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: important.resource.com
signature: sig=:o1zEVnjJ2NMRHQn3QT6GFMEdTCxSudDKb9OgUDXzUZ6OpMw4hjTVnbmzx_Hb_mhFdeuvORvPFhy-aqVBA50XBQ:
signature-input: sig=("@method" "@authority" "@path" "signature-key");created=1774920963
signature-key: sig=(scheme=hwk kty="OKP" crv="Ed25519" x="gHvo19V3SU42BI4K4rhOKMfMnA9WW0qD18wdbwJm-vY")
user-agent: python-httpx/0.28.1
================================================================================


================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 200
content-length: 90
content-type: application/json

[Body (90 bytes)]
{"message":"Access granted","data":"This is protected data","scheme":"hwk","method":"GET"}
================================================================================
```

## Resource Verification Process

When the resource receives this request, it performs these steps:

### 1. Label Consistency Check
The resource verifies that `sig` appears identically in all three headers:
- `Signature-Input: sig=...`
- `Signature: sig=...`
- `Signature-Key: sig=...`

If labels don't match, the request is rejected.

### 2. Signature-Key Coverage Check
The resource confirms that `"signature-key"` is listed in the covered components. This prevents **scheme substitution attacks** where an attacker could:
- Intercept an HWK-signed request
- Republish the same public key under their own `jwks_uri` identity
- Swap the `Signature-Key` header to claim the request as their own

### 3. Timestamp Validation
The `created` timestamp must be within an acceptable window (typically ±60 seconds). Stale signatures are rejected to prevent replay attacks.

### 4. Signature Base Reconstruction
The resource reconstructs the exact bytes that were signed:
```
"@method": GET
"@authority": important.resource.com
"@path": /data
"signature-key": sig=(scheme=hwk kty="OKP" crv="Ed25519" x="gHvo19V3SU42BI4K4rhOKMfMnA9WW0qD18wdbwJm-vY")
"@signature-params": ("@method" "@authority" "@path" "signature-key");created=1774920963
```

### 5. Public Key Extraction
For `scheme=hwk`, the resource extracts the key directly from the header, no network fetch required:
- Parse `kty`, `crv`, and `x` parameters
- Reconstruct the Ed25519 public key

### 6. Signature Verification
Using the extracted public key, verify the signature over the reconstructed signature base.

### 7. Apply Policy
Even with a valid signature, the resource decides what access to grant. For pseudonymous requests, this typically means:
- Rate limiting per public key (the `x` value acts as a stable identifier)
- Logging for abuse detection
- Possibly lower access tier than identified agents

The demo also exercises a signed `POST` with a JSON body:

```bash
================================================================================
>>> AGENT REQUEST to https://important.resource.com/data
================================================================================
POST https://important.resource.com/data HTTP/1.1
Content-Type: application/json
Signature: sig=:mY9fPQwARVAj3bWJPETXXnJHH1RAVgf-2HZYUtrSnQiFpFwzx1O7NeF8s8wVJ3JaIa7qTe0lDN2fFwUG3F25BQ:
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1774920963
Signature-Key: sig=(scheme=hwk kty="OKP" crv="Ed25519" x="gHvo19V3SU42BI4K4rhOKMfMnA9WW0qD18wdbwJm-vY")

[Body (41 bytes)]
{"action": "create", "data": "test data"}
================================================================================
```

Agent gets the signed `GET` response:

```bash
================================================================================
<<< AGENT RESPONSE from https://important.resource.com/data
================================================================================
HTTP/1.1 200 OK
content-length: 90
content-type: application/json
date: Tue, 31 Mar 2026 01:36:03 GMT
server: uvicorn

[Body (90 bytes)]
{"message":"Access granted","data":"This is protected data","scheme":"hwk","method":"GET"}
================================================================================
```

And for the signed `POST`, the response reflects the method change:

```bash
================================================================================
<<< AGENT RESPONSE from https://important.resource.com/data
================================================================================
HTTP/1.1 200 OK
content-length: 91
content-type: application/json
date: Tue, 31 Mar 2026 01:36:03 GMT
server: uvicorn

[Body (91 bytes)]
{"message":"Access granted","data":"This is protected data","scheme":"hwk","method":"POST"}
================================================================================
```

## When to Use HWK

The pseudonymous tier is ideal for:

| Use Case | Why HWK Works |
|----------|---------------|
| **Web crawlers** | Prove you're a consistent bot without revealing operator identity |
| **Rate limiting** | Resources can track requests per-key without requiring registration |
| **Progressive trust** | Start pseudonymous, upgrade to identified (`scheme=jwks_uri`) if you need higher limits |
| **Privacy-preserving agents** | Avoid disclosing organizational identity during exploratory access |
| **Testing and development** | Access APIs without going through registration flows |

**Key reuse considerations:**
- Reusing the same key across requests enables **reputation building** (the resource sees consistent behavior)
- But it also enables **tracking**—the resource can correlate all requests from that key
- For maximum privacy, generate a fresh keypair per session or per resource


## Where to Next

In this flow, we reviewed the pseudonymous access pattern with AAuth. But if we need a more durable, provable, cryptographic identity, we need to use AAuth's JWKS scheme. We [review those flows in the next section](./flow-02-jwks.md). 

[← Back to index](index.md)
