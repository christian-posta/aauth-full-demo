---
layout: default
title: Agent authorization (on behalf of)
---

# Agent authorization (with User Consent)

In this demo, we'll explore how Agent Identity Authorization works when user consent is required. This builds on the [autonomous authorization flow](./agent-authorization-autonomous.md) but adds a critical dimension: user delegation. When an agent needs to act on behalf of a user, the authorization server (Keycloak) ensures the user explicitly grants permission.

[← Back to index](index.md)

## Watch the demo

<div style="position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden; max-width: 100%; margin: 1em 0;">
  <iframe style="position: absolute; top: 0; left: 0; width: 100%; height: 100%;" src="https://www.youtube.com/embed/J96tIVf8dVI" title="Agent authorization (on behalf of) Demo" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>
</div>

## Set up Keycloak to Require Consent

First, we need to tell Keycloak which scopes require user consent. With Keycloak running, execute the consent configuration script:


```bash
./keycloak/set_aauth_consent_attributes.sh 

==============================================
  AAuth Consent Attributes Configuration
==============================================

Keycloak: http://localhost:8080
Realm:    aauth-test

Connecting to Keycloak...

What would you like to do?
  1) Scopes only   - configure exact scope names (e.g. openid, profile, email)
  2) Prefixes only - configure scope prefixes (e.g. user., profile., email.)
  3) Both scopes and prefixes
  4) Use defaults for both
  5) View current scopes/prefixes
  6) Clear scopes and prefixes (set to empty)
  7) Quit (no changes)

Choice [1-7]: 
```


Choose `1` for scopes only, then configure `supply-chain:optimize` as a scope requiring user consent:


```bash
Choice [1-7]: 1

--- Configure scopes ---
  Examples: openid, profile, email
  Default:  ["openid","profile","email"]

Enter scopes (comma-separated, or press Enter for default): supply-chain:optimize

Summary:
  Scopes:   [  "supply-chain:optimize"]
  Prefixes: ["user.","profile.","email."]

Apply these to Keycloak? [Y/n]: 
```

Hit ENTER to continue and you should see keycloak updated:

```bash
Applying to Keycloak...
✅ Successfully set AAuth consent attributes for realm 'aauth-test'!

Configured values:
  aauth.consent.required.scopes:         ["supply-chain:optimize"]
  aauth.consent.required.scope.prefixes: ["user.","profile.","email."]

Non-interactive usage:
  export AAUTH_CONSENT_SCOPES='["openid","profile","email"]'
  export AAUTH_CONSENT_PREFIXES='["user.","profile.","email."]'
  ./keycloak/set_aauth_consent_attributes.sh http://localhost:8080 aauth-test admin admin
```

Now restart the `supply-chain-agent` with user-delegated authorization:

<div class="run-tabs">
  
  <input type="radio" name="run-tabs" id="tab-supply-chain" checked>
  <input type="radio" name="run-tabs" id="tab-market-analysis">
  <div class="tab-labels">
    <label for="tab-supply-chain">Supply-chain-agent</label>
    <label for="tab-market-analysis">Market-analysis</label>
  </div>
  <div class="tab-content" id="content-supply-chain">
    <p>From the <code>supply-chain-agent</code> directory:</p>
    <pre><code>
      > cd supply-chain-agent
      > uv run . --signature-scheme jwks --authorization-scheme user-delegated
    </code></pre>
  </div>
  <div class="tab-content" id="content-market-analysis">
    <p>From the <code>market-analysis-agent</code> directory:</p>
    <pre><code>
      > cd market-analysis-agent
      > uv run . --signature-scheme jwks --authorization-scheme autonomous
    </code></pre>
  </div>
</div>


Navigate to the UI and click "Optimize Laptop Supply Chain". The flow now includes an additional step for user consent:

```mermaid
sequenceDiagram
  participant UI as UI
  participant BE as Backend
  participant KC as Keycloak
  participant SCA as Supply-Chain Agent

  UI->>BE: 1. User clicks "Optimize Laptop Supply Chain"
  BE->>SCA: 2. POST /optimize (signed request)
  SCA-->>BE: 3. 401 + resource_token
  BE->>KC: 4. Exchange resource_token
  KC-->>BE: 5. request_token (consent required)
  BE-->>UI: 6. Return request_token
  UI->>KC: 7. User consent flow
  KC-->>UI: 8. consent_token
  UI->>BE: 9. Submit consent_token
  BE->>KC: 10. Exchange consent_token for auth_token
  KC-->>BE: 11. auth_token (with sub + agent)
  BE->>SCA: 12. Retry with auth_token
  SCA-->>BE: 13. Success
```


## Step By Step

### 1. Initial Request Fails (401)

When the `backend` calls the `supply-chain-agent`, it receives a 401 with a resource token (same as autonomous flow):


```bash
INFO:aauth.tokens:🔐 401 from supply-chain-agent (url=http://supply-chain-agent.localhost:3000): headers={'date': 'Sat, 07 Feb 2026 16:56:35 GMT', 'server': 'uvicorn', 'agent-auth': 'httpsig; auth-token; resource_token="eyJhbGciOiJFZERTQSIsImtpZCI6InN1cHBseS1jaGFpbi1hZ2VudC1lcGhlbWVyYWwtMSIsInR5cCI6InJlc291cmNlK2p3dCJ9.eyJpc3MiOiJodHRwOi8vc3VwcGx5LWNoYWluLWFnZW50LmxvY2FsaG9zdDozMDAwIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9hYXV0aC10ZXN0IiwiYWdlbnQiOiJodHRwOi8vYmFja2VuZC5sb2NhbGhvc3Q6ODAwMCIsImFnZW50X2prdCI6IlVDaWE5dEpNV3lEMWZPMGlhV1YxV2NzQmRaQzIwb0E5MVZYLS1VY2NXM0UiLCJleHAiOjE3NzA0ODM2OTYsInNjb3BlIjoic3VwcGx5LWNoYWluOm9wdGltaXplIG1hcmtldC1hbmFseXNpczphbmFseXplIn0.jHesCOn3qIXke_aAe3VrIzS7RbLhW9_rMRfLNqVeMDC9YZl16a1RvOEELHiy0wXA-Cy7y3CUzW7t5N_FbxgiCA"; auth_server="http://localhost:8080/realms/aauth-test"', 'content-length': '22', 'content-type': 'text/plain; charset=utf-8'}
```
{: .log-output}

### 2. Keycloak Detects Consent Required

The backend exchanges the resource token at Keycloak. But this time, Keycloak recognizes that supply-chain:optimize requires user consent and returns a request_token instead of an auth_token:

```bash
INFO:aauth.tokens:🔐 Received request_token from auth server (user consent required): 6cd2d825-158b-4efb-93da-f4e73a499d8a.1770483396.NmNkMmQ4MjUtMTU4Yi00ZWZiLTkzZGEtZjRlNzNhNDk5ZDhhOjE3NzA0ODMzOTY6aHR0cDovL2JhY2tlbmQubG9jYWxob3N0OjgwMDA
```
{: .log-output}

### 3. User Consent Screen

The UI presents the consent screen to the user:

![](./images/user-consent.png)

The user sees:

* Which agent is requesting access (backend)
* What scopes are being requested (supply-chain:optimize)
* The ability to approve or deny


### 4. Authorization Token with User Identity

After the user approves, the backend exchanges the consent token for an auth_token. The supply-chain-agent receives:

```bash
INFO:agent_executor:✅ AAuth signature verification successful
INFO:aauth.tokens:🔐 Received auth_token in request (HTTPSig scheme=jwt): eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiYXV0aCtqd3QiLCJraWQiIDogIjF2SGZlTWk5U0E4VTdWZlNKRTN3SnVTQklOZUhVeWpOY0pzZ2tYWWNHQlkifQ.eyJleHAiOjE3NzA0ODM3NjUsImlhdCI6MTc3MDQ4MzQ2NSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9hYXV0aC10ZXN0IiwiYXVkIjoiaHR0cDovL3N1cHBseS1jaGFpbi1hZ2VudC5sb2NhbGhvc3Q6MzAwMCIsInN1YiI6IjAwYjUxOWU4LWY0MDktNDIwMS04OTExLTFjYjQwOGU4YTA4MiIsImFnZW50IjoiaHR0cDovL2JhY2tlbmQubG9jYWxob3N0OjgwMDAiLCJjbmYiOnsiandrIjp7ImtpZCI6IkdmWHZZS3ZscktGb3V2S1JQdUFnbFJZX3RiTmJJTFpMRzJBaTJNd2l6bVUiLCJrdHkiOiJPS1AiLCJ1c2UiOiJzaWciLCJjcnYiOiJFZDI1NTE5IiwieCI6IklDSEVXYUwyRTBFaGJkU3F4eGZ5ZUY4RjF5WndiNEViQzJKQXZ0dl9ZR3cifX0sInNjb3BlIjoic3VwcGx5LWNoYWluOm9wdGltaXplIG1hcmtldC1hbmFseXNpczphbmFseXplIn0.NAsgPE4DHrS36m98J76QbsZHWj9EIYJzVg1mqa5IJv6xp6lRbsqYO7jnqodh5QV86yhrLpBWpVzyrSYm1LU9DJnh8VegIR9JWUwO-c9j4xdFIQLdDIAzCMalCUTWnC2E2dwZA1raaw3kxxJ1eKkIOWQqWRp-oeubHdtoqI2yJHbVZNs1VQ7YeajGygyEHFG3W7F1eWpt8TChF8sy5gvqvk5DPiHXRykyxpghK-klq4hzQACIAXoFhtBUo8zqYFtF_gtSkQPcs_CdNhjp5ksr-ZkyqpXQjhBmajaARNGoVxUtdAtVOyoz4wFSFwBTTYpFg-f4IrkjA-kwCE-_71UZ5A
INFO:agent_executor:🔐 Auth token detected in request (scheme=jwt)
INFO:httpx:HTTP Request: GET http://localhost:8080/realms/aauth-test/protocol/openid-connect/certs "HTTP/1.1 200 OK"
INFO:agent_executor:✅ Auth token verified successfully
INFO:agent_executor:✅ Authorization successful: auth_token verified for agent: http://backend.localhost:8000
```
{: .log-output}

If we decode the token:

```json
{
  "exp": 1770483765,
  "iat": 1770483465,
  "iss": "http://localhost:8080/realms/aauth-test",
  "aud": "http://supply-chain-agent.localhost:3000",
  "sub": "00b519e8-f409-4201-8911-1cb408e8a082",
  "agent": "http://backend.localhost:8000",
  "cnf": {
    "jwk": {
      "kid": "GfXvYKvlrKFouvKRPuAglRY_tbNbILZLG2Ai2MwizmU",
      "kty": "OKP",
      "use": "sig",
      "crv": "Ed25519",
      "x": "ICHEWaL2E0EhbdSqxxfyeF8F1yZwb4EbC2JAvtv_YGw"
    }
  },
  "scope": "supply-chain:optimize market-analysis:analyze"
}
```

## Compare to Autonomous Scheme

Compare this to the [autonomous auth flow token](./agent-authorization-autonomous.md#walking-through-the-demo-flow):

| Claim | Autonomous | User-Delegated | Meaning |
|-------|-----------|----------------|---------|
| **sub** | ❌ Not present | ✅ `"00b519e8..."` | **User identity** - who authorized this action |
| **agent** | ✅ `"http://backend..."` | ✅ `"http://backend..."` | **Agent identity** - which agent is acting |
| **cnf** | ✅ Bound to agent's key | ✅ Bound to agent's key | **Proof-of-possession** - only this agent can use the token |


## How This Relates to OIDC

If you're familiar with OAuth 2.0 and OpenID Connect, this pattern should feel familiar:

- **OIDC login** establishes the user's identity (`sub` claim in ID token)
- **User consent** grants the agent permission to act with specific scopes
- **Auth token** carries both user identity (`sub`) and agent identity (`agent`)

The key innovation of AAuth is **dual identity**:
- Traditional OAuth: tokens represent either the user OR the application
- AAuth: tokens represent the user AND the agent simultaneously

This enables fine-grained audit trails: "User Alice authorized Backend Agent to optimize the supply chain at 4:56 PM on February 7th, 2026."

## Summary

Use autonomous mode when: Agents are acting on their own authority (background jobs, system tasks, agent-to-agent coordination).

Use user-delegated mode when: Agents must act on behalf of a specific user (accessing user data, making decisions with user accountability, compliance requirements).

In the next post, we'll explore token exchange and delegation chains - how agents can delegate to other agents while preserving the user's identity and consent.

[← Back to index](index.md)