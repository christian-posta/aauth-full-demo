Summary of what’s implemented and what’s left:

---

## Implemented (backend – plan steps 1–4)

### 1. **Backend AAuth token service** (`backend/app/services/aauth_token_service.py`)
- **`request_token` handling:** If Keycloak returns `request_token` and no `auth_token`, the service now returns `{request_token, expires_in, consent_required: True}`.
- **`get_consent_url(request_token, redirect_uri, state=None)`:** Builds the user consent URL from `agent_auth_endpoint` (metadata or env).
- **`exchange_code_for_token(code, redirect_uri)`:** POSTs to `agent_token_endpoint` with `request_type=code`, `code`, `redirect_uri` and returns `{auth_token, refresh_token, expires_in}`.
- **`agent_auth_endpoint`:** Added `_get_agent_auth_endpoint()` and use of `KEYCLOAK_AAUTH_AGENT_AUTH_ENDPOINT` or metadata.

### 2. **Backend callback** (`backend/app/api/auth.py`)
- **GET `/auth/aauth/callback`:** Accepts `code`, `state` (and optional `error`, `error_description`). Calls `exchange_code_for_token`, resolves pending request by `state` (= `request_id`), starts the optimization workflow with the new `auth_token`, and redirects to the frontend with `?aauth_authorized=1&request_id=...` or `?aauth_error=1&...` on failure.
- **Helpers:** `_aauth_callback_redirect_uri()` and `_frontend_redirect_base()` for redirect URLs.

### 3. **Backend A2A service** (`backend/app/services/a2a_service.py`)
- **Consent handling:** When `request_auth_token` returns `consent_required` and `request_token`, the service returns `{type: "consent_required", consent_required: True, consent_url, request_id}` and does **not** retry the A2A call.
- **`request_id`:** Optional `request_id` is passed into `optimize_supply_chain` and used as `state` in the consent URL.
- **Redirect URI:** Updated from `/aauth/callback` to `/auth/aauth/callback`.

### 4. **Backend optimization API** (`backend/app/api/optimization.py`)
- **Two-phase start when `AAUTH_AUTHORIZATION_SCHEME=user-delegated`:**
  - Create `request_id`, then a **sync** call to `a2a_service.optimize_supply_chain(..., request_id=request_id)`.
  - If **consent_required:** store pending via `optimization_service.set_pending_aauth_request(...)` and return `200` with `{consent_required: true, consent_url, request_id}` (no background task).
  - If **success:** run workflow with `precomputed_response=result` and return `{request_id, status: "completed", ...}`.
  - If **error / other:** update progress, mark failed, return error payload.
- **`run_optimization_workflow`:** New optional `precomputed_response`; when set, the A2A call is skipped and that response is used.

### 5. **Optimization service** (`backend/app/services/optimization_service.py`)
- **Pending AAuth store:** `set_pending_aauth_request(request_id, user_id, request, trace_context)` and `get_and_clear_pending_aauth_request(request_id)` for the consent → callback flow.

### 6. **Config** (`backend/env.example`)
- Documented `AAUTH_AUTHORIZATION_SCHEME=user-delegated`, `AAUTH_CALLBACK_URL`, `AAUTH_FRONTEND_REDIRECT_URL`, and `KEYCLOAK_AAUTH_AGENT_AUTH_ENDPOINT`.

---

## Not yet done (plan steps 5–7)

- **5. Supply-chain-agent:** Token exchange service, interceptor `auth_token`/`scheme=jwt` for MAA, and handling 401-from-MAA (exchange + retry with jwt).
- **6. Market-analysis-agent:** Resource token issuance, 401 Agent-Auth, and scheme=jwt verification (including `act`).
- **7. Frontend (supply-chain-ui):** On `consent_required: true` + `consent_url`, redirect user to `consent_url`; after redirect with `?aauth_authorized=1&request_id=...`, poll progress for that `request_id` (or call a resume/retry endpoint if you add one).

Backend user-delegated AAuth (steps 1–4) is implemented. Say whether you want to move on to supply-chain-agent (5), market-analysis-agent (6), or the UI (7) next, and we can do that next.