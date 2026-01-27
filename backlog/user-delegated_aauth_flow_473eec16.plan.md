---
name: User-Delegated AAuth Flow
overview: "Implement user-delegated AAuth (SPEC 3.6) on top of the existing autonomous flow (SPEC 3.4). The backend already has token service, challenge handling, and scheme=jwt support; supply-chain-agent already acts as resource and verifies auth tokens. The main additions are: (1) backend handling of request_token and user consent (get_consent_url, exchange_code_for_token, callback endpoint), (2) A2A/optimization API returning consent_required when Keycloak demands user consent, (3) supply-chain-agent token exchange and scheme=jwt for downstream MAA calls, (4) market-analysis-agent acting as resource and verifying auth tokens including act claim."
todos: []
isProject: false
---

# User-Delegated AAuth Flow — Updated Implementation Plan

## Current State (Autonomous Flow — Already Working)

Autonomous agent auth (SPEC 3.4) is implemented and working between backend and supply-chain-agent. Relevant code:

**Backend**

- [backend/app/services/aauth_token_service.py](backend/app/services/aauth_token_service.py): `request_auth_token(resource_token, redirect_uri)` calls Keycloak with `request_type=auth` and **only handles direct-grant responses** (`auth_token` + `refresh_token`). No handling of `request_token` (user consent required).
- [backend/app/services/aauth_interceptor.py](backend/app/services/aauth_interceptor.py): Supports `scheme=jwt` when `auth_token` is passed; `scheme=jwks`/`scheme=hwk` otherwise. Uses `AAUTH_SIGNATURE_SCHEME` and accepts `auth_token` in constructor.
- [backend/app/services/a2a_service.py](backend/app/services/a2a_service.py): On 401 + Agent-Auth, parses `resource_token` and `auth_server`, calls `aauth_token_service.request_auth_token()`, expects direct `auth_token`, caches it, retries with a new client that has `auth_token`. No user-consent path.
- [backend/app/api/auth.py](backend/app/api/auth.py): Has `/me`, `/health`. **No** `/auth/aauth/callback` route.
- [backend/env.example](backend/env.example): `AAUTH_AUTHORIZATION_SCHEME=autonomous`; no `agent_auth_endpoint`-related vars.

**Supply-chain-agent**

- [supply-chain-agent/resource_token_service.py](supply-chain-agent/resource_token_service.py): Generates resource_token (iss, aud, agent, agent_jkt, scope, exp). **Done.**
- [supply-chain-agent/agent_executor.py](supply-chain-agent/agent_executor.py): Verifies hwk/jwks/jwt; when `AAUTH_AUTHORIZATION_SCHEME=autonomous` and auth is missing/invalid, issues resource_token and returns 401 with Agent-Auth. **Acts as resource — done.** JWT branch verifies auth_token via Keycloak JWKS and uses agent identity; user identity (`sub`) is not yet used for policy.
- [supply-chain-agent/aauth_interceptor.py](supply-chain-agent/aauth_interceptor.py): Only HWK/JWKS, **no** `auth_token` parameter — used for calls to market-analysis-agent.

**Market-analysis-agent**

- [market-analysis-agent/agent_executor.py](market-analysis-agent/agent_executor.py): Verifies hwk and jwks only. **No** scheme=jwt verification, **no** resource_token issuance, **no** 401 Agent-Auth. Today it accepts any valid AAuth signature (HWK/JWKS) and proceeds.

---

## What the User-Delegated Flow Adds (SPEC 3.6 + 9.4–9.6, 9.10)

When `AAUTH_AUTHORIZATION_SCHEME=user-delegated`:

1. **Backend ↔ Keycloak**: If Keycloak returns `request_token` (user consent required per SPEC 9.4), backend must:

- Expose consent URL: `agent_auth_endpoint?request_token=...&redirect_uri=...`
- Implement callback: GET `/auth/aauth/callback?code=...&state=...` → exchange code for `auth_token`, then either store and redirect, or trigger the pending optimization with that token.

2. **Backend ↔ UI**: When backend gets `request_token` from Keycloak, it must **not** retry the A2A call in the background; it must return a response that tells the frontend “user consent required” and provide the consent URL (and e.g. `request_id` for state).
3. **Supply-chain-agent ↔ Market-analysis-agent**: When SCA calls MAA and gets 401 + resource_token, SCA must perform **token exchange** (SPEC 9.10) with Keycloak (`request_type=exchange`, upstream auth_token in Signature-Key) and then call MAA with `scheme=jwt` and the new auth_token.
4. **Market-analysis-agent**: Must be able to act as **resource** (issue resource_token, return 401 Agent-Auth when authorization is required) and to **verify** auth tokens (`scheme=jwt`), including `act` for delegation.

---

## Implementation Plan

### 1. Backend: AAuth token service — request_token path and code exchange

**File:** [backend/app/services/aauth_token_service.py](backend/app/services/aauth_token_service.py)

- In `request_auth_token()`, after calling Keycloak, branch on the response:
- If response has **`auth_token`**: keep current behavior (return `{auth_token, refresh_token, expires_in}`).
- If response has **`request_token`** (and no `auth_token`): return e.g. `{request_token, expires_in, consent_required: True}`.
- Add **`get_consent_url(request_token, redirect_uri)`**:
- Use `agent_auth_endpoint` from metadata (fetch from `/.well-known/aauth-issuer` or cache).
- Return `{agent_auth_endpoint}?request_token={request_token}&redirect_uri={redirect_uri}` (plus optional `state`).
- Add **`exchange_code_for_token(code, redirect_uri)`** (SPEC 9.6):
- POST to `agent_token_endpoint` with `request_type=code`, `code`, `redirect_uri`.
- Sign with backend’s key (same as today).
- Return `{auth_token, refresh_token, expires_in}`.
- Ensure metadata fetching/caching provides **`agent_auth_endpoint`** (SPEC 8.2); add/cache it where you already cache `agent_token_endpoint`.

No new files; extend the existing token service.

---

### 2. Backend: Callback endpoint

**File:** [backend/app/api/auth.py](backend/app/api/auth.py) (or a new router under the same app)

- Add **GET (or POST) `/auth/aauth/callback`**:
- Query params: `code`, `state` (and optionally `redirect_uri` if not fixed).
- Call `aauth_token_service.exchange_code_for_token(code, redirect_uri)`.
- **State handling:** Use `state` to associate the token with the pending flow. Recommended: `state = request_id` (or a compound like `request_id|user_id`). Backend must have stored “pending optimization” when it previously returned `consent_required` (see step 4).
- After exchange: store `auth_token` (and refresh) keyed by `state` or by user/session (implementation choice: in-memory dict, Redis, or DB). If using `request_id`:
 - Attach `auth_token` to that optimization request (e.g. in `optimization_service` or a small “AAuth consent state” store).
 - Redirect browser to frontend with e.g. `/?aauth_authorized=1&request_id={request_id}` so the UI can retry or resume.
- If exchange fails, redirect to frontend with an error query param.

**Routing:** Ensure the callback URL is registered in the app (e.g. in [backend/app/main.py](backend/app/main.py)) and that `redirect_uri` used in consent and in Keycloak matches this exact path (e.g. `http://backend.localhost:8000/auth/aauth/callback`).

---

### 3. Backend: A2A service — handle consent_required

**File:** [backend/app/services/a2a_service.py](backend/app/services/a2a_service.py)

When handling the Agent-Auth challenge:

- Call `request_auth_token(resource_token, redirect_uri)` as today.
- If the result contains **`consent_required` and `request_token`**:
- Do **not** retry the A2A request.
- Call `get_consent_url(request_token, redirect_uri)` (or have token service return it in the same result).
- Raise or return a structured outcome that the API layer can use, e.g. `A2AConsentRequired(consent_url=..., request_id=..., state=...)`, or return a small dict `{consent_required: True, consent_url: "...", state: "..."}` so the caller can tell the frontend to send the user to `consent_url` and use `state` in the callback.

Design choice to implement:

- **Option A (recommended):** Optimization “start” in user-delegated mode is **two-phase**.  
- Phase 1: Sync call that may call SCA, get 401, call Keycloak; if `request_token` then **do not** start the background task; create `request_id`, store “pending (request_id, user_id, request)” and return `{consent_required: true, consent_url, request_id, state: request_id}`.  
- Phase 2: When the callback is hit with `code` and `state=request_id`, backend exchanges code, stores auth_token for that `request_id`, then **starts** the background task for that stored request with the new `auth_token`. Redirect to frontend with `?aauth_authorized=1&request_id=...`.
- **Option B:** Start background task immediately; on 401 + request_token, task stores “needs consent” and exits; a separate “resume” or “retry” endpoint is called by the frontend after redirect, which looks up stored auth_token by request_id and runs the workflow. This requires a way to “resume” by request_id and a clear contract for when the frontend calls it.

The backlog’s “retry original request with scheme=jwt” is satisfied by either option as long as the eventual A2A call uses the token obtained from the code exchange.

---

### 4. Backend: Optimization API — consent_required response and callback-driven start

**File:** [backend/app/api/optimization.py](backend/app/api/optimization.py)

- When **user-delegated** and start flow is synchronous (phase 1):
- If A2A returns “consent required” (structured result from step 3), respond with **200** and body e.g. `{ consent_required: true, consent_url: "...", request_id: "..." }` instead of starting the background task.
- Frontend must redirect the user to `consent_url`; `redirect_uri` passed to Keycloak must point at backend `/auth/aauth/callback`, and `state` should be `request_id` (or whatever the backend uses to reconnect after consent).
- When **callback** runs (step 2), it starts the background task for that `request_id` with the newly obtained `auth_token`. No change to `run_optimization_workflow` signature beyond passing that `auth_token` as you already do.
- Optional: Add **GET `/optimization/aauth-status/{request_id}`** or similar so the frontend can poll after redirect until the run has started or failed.

**File:** [backend/app/main.py](backend/app/main.py)

- Ensure the auth router that mounts the callback is included and that CORS and routing allow the callback to be hit from the browser redirect.

---

### 5. Supply-chain-agent: Token exchange service

**New file:** `supply-chain-agent/aauth_token_service.py` (or equivalent module name)

- Implement **token exchange** (SPEC 9.10):
- `exchange_token(upstream_auth_token: str, resource_token: str, auth_server_url: str) -> dict`
- POST to auth server’s `agent_token_endpoint` with `request_type=exchange`, `resource_token`.
- Sign with SCA’s key; set `Signature-Key: sig=(scheme=jwt jwt="<upstream_auth_token>")`.
- Return `{auth_token, expires_in}` (exchange does not return refresh_token).
- Use Keycloak AAuth issuer/agent_token_endpoint (env: `KEYCLOAK_AAUTH_ISSUER_URL` or similar). Reuse SCA’s existing signing (from [supply-chain-agent/aauth_interceptor.py](supply-chain-agent/aauth_interceptor.py) / `get_signing_keypair`).

---

### 6. Supply-chain-agent: AAuth interceptor — scheme=jwt and auth_token for MAA

**File:** [supply-chain-agent/aauth_interceptor.py](supply-chain-agent/aauth_interceptor.py)

- Add an optional **`auth_token`** argument to the interceptor (same pattern as backend’s [backend/app/services/aauth_interceptor.py](backend/app/services/aauth_interceptor.py)).
- When `auth_token` is set, use **`scheme=jwt`** and put the auth_token in `Signature-Key` for requests to the market-analysis-agent. When `auth_token` is None, keep current behavior (HWK or JWKS).

---

### 7. Supply-chain-agent: Handle Agent-Auth challenges from MAA and token exchange

**File:** [supply-chain-agent/agent_executor.py](supply-chain-agent/agent_executor.py) and the place that builds the MAA client (e.g. `_get_market_analysis_client` and `_get_market_analysis`).

- When calling the market-analysis-agent, if the client gets **401** with an **Agent-Auth** header:
- Parse `resource_token` and `auth_server`.
- If the incoming request to SCA carried an auth_token (e.g. from backend’s user-delegated flow), pass that into the new token exchange service as `upstream_auth_token`.
- Call `exchange_token(upstream_auth_token, resource_token, auth_server)`.
- Build a new MAA client (or reuse) with the exchanged `auth_token` in the interceptor and **retry** the MAA request with `scheme=jwt`.

This requires the executor to have access to the “current” auth_token when it invokes MAA (e.g. from the request context or from a context variable set in the executor when handling the incoming scheme=jwt request from the backend). If the incoming call is already with scheme=jwt, that auth_token is the “upstream” token for exchange.

---

### 8. Market-analysis-agent: Act as resource and verify auth tokens

**Files:**

- New (or existing) helper for resource tokens, e.g. `market-analysis-agent/resource_token_service.py` (mirror [supply-chain-agent/resource_token_service.py](supply-chain-agent/resource_token_service.py)), and  
- [market-analysis-agent/agent_executor.py](market-analysis-agent/agent_executor.py)

- **Resource behavior:**  
- When MAA is configured to require “auth-token” (e.g. via `AAUTH_AUTHORIZATION_SCHEME` or similar), and the request has no valid auth_token (or only HWK/JWKS and policy requires user-delegated):
 - Issue a **resource_token** binding the calling agent (SCA) and scope to MAA’s identity.
 - Return **401** with `Agent-Auth: httpsig; auth-token; resource_token="..."; auth_server="..."`.
- **Verification:**  
- Add a **scheme=jwt** verification branch:
 - Resolve signing key from the auth_token (Keycloak JWKS; same pattern as in supply-chain-agent).
 - Verify JWT (signature, typ, aud, exp, agent, cnf, and optionally **act**).
 - Use `aud` = MAA’s resource ID; accept tokens where `agent` is SCA; if `act` is present, validate delegation chain as needed.

MAA’s env should include `KEYCLOAK_AAUTH_ISSUER_URL` (or equivalent) and a resource identifier for `aud` (e.g. `MARKET_ANALYSIS_AGENT_ID_URL`).

---

### 9. Configuration and env

**Files:**
[backend/env.example](backend/env.example), [supply-chain-agent/env.example](supply-chain-agent/env.example), [market-analysis-agent/env.example](market-analysis-agent/env.example)

- **Backend:**  
- Document `AAUTH_AUTHORIZATION_SCHEME=user-delegated` and, when used, the callback URL (e.g. `AAUTH_CALLBACK_URL` or derive from `BACKEND_AGENT_URL` + `/auth/aauth/callback`).  
- Ensure `KEYCLOAK_AAUTH_ISSUER_URL` (and optional `KEYCLOAK_AAUTH_AGENT_TOKEN_ENDPOINT`) are set; backend already uses these.
- **Supply-chain-agent:**  
- Add `KEYCLOAK_AAUTH_ISSUER_URL` (and optionally agent token endpoint) for token exchange.
- **Market-analysis-agent:**  
- Add `KEYCLOAK_AAUTH_ISSUER_URL` and a resource-id env (e.g. `MARKET_ANALYSIS_AGENT_ID_URL`) for issuing resource_token and validating auth_token `aud`.

---

### 10. Frontend (supply-chain-ui)

**Scope:**

- When backend returns `consent_required: true` and `consent_url`, open or redirect the user to `consent_url` (and, if needed, pass `request_id` via `state` or another agreed param).  
- After consent, backend redirects to the UI with e.g. `?aauth_authorized=1&request_id=...`. The UI should then either poll progress for that `request_id` or call a “resume”/“retry” endpoint if you adopt that contract.  
- No AAuth token needs to be stored in the UI if the backend associates the token with `request_id` (or user/session) and completes the flow server-side.

---

## Summary of Backlog vs Current Code

| Backlog item | Status | Notes |
|--------------|--------|-------|
| SCA issue resource tokens | **Done** | `resource_token_service` + executor 401 with Agent-Auth |
| Backend AAuth token service (request_token, consent URL, code exchange) | **Partial** | Has request_auth_token (direct only). Add request_token branch, get_consent_url, exchange_code_for_token |
| Backend callback endpoint | **New** | Add GET /auth/aauth/callback |
| Backend interceptor scheme=jwt | **Done** | Already supports jwt when auth_token is provided |
| Backend A2A handle challenges, extract resource_token, request auth_token | **Done** for direct grant | Add branch when response is request_token → return consent_required, do not retry |
| SCA verify auth tokens (scheme=jwt), extract user identity | **Done** (verify); **Optional** (user identity) | Add use of `sub` for policy if needed |
| SCA token exchange service (9.10) | **New** | New module + exchange_token(upstream_auth_token, resource_token, ...) |
| SCA interceptor scheme=jwt for downstream | **New** | Add auth_token param and scheme=jwt branch |
| SCA handle challenges from MAA | **New** | On 401 from MAA, exchange token, retry with jwt |
| MAA issue resource tokens | **New** | Resource_token helper + 401 Agent-Auth when required |
| MAA verify auth tokens (scheme=jwt), user identity, act | **New** | JWT verification branch + Keycloak JWKS + act |
| Config (env.example) | **Partial** | Add user-delegated and MAA/SCA AAuth vars |

---

## Suggested Order of Work

1. **Backend token service** — request_token handling, get_consent_url, exchange_code_for_token, and agent_auth_endpoint in metadata.
2. **Backend callback** — GET /auth/aauth/callback, state = request_id, store auth_token and start pending task (or return token to be used by a separate “resume” call).
3. **Backend A2A + optimization API** — consent_required branch, two-phase start when user-delegated, and wiring so callback starts the workflow with the new auth_token.
4. **Supply-chain-agent** — token exchange service, interceptor auth_token/jwt, and “on 401 from MAA → exchange → retry with jwt” in the executor / MAA client.
5. **Market-analysis-agent** — resource_token issuance and 401 Agent-Auth; scheme=jwt verification (including act if present).
6. **Config and UI** — env examples and minimal frontend changes for redirect to consent_url and post-callback behavior.

---

## Key SPEC References

- **User-delegated flow:** SPEC §3.6  
- **Auth response (request_token vs direct grant):** SPEC §9.4  
- **User consent flow (agent_auth_endpoint, redirect):** SPEC §9.5  
- **Code exchange:** SPEC §9.6  
- **Token exchange (multi-hop):** SPEC §9.10  
- **Resource tokens:** SPEC §6  
- **Auth server metadata (agent_auth_endpoint, agent_token_endpoint):** SPEC §8.2  