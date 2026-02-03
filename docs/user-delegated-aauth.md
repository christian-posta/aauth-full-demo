---
layout: default
title: User-Delegated AAuth Flow
permalink: /user-delegated-aauth/
---

# User-Delegated AAuth Flow

This document describes the **user-delegated AAuth** implementation: user consent, auth tokens (`scheme=jwt`), resource tokens, and multi-hop token exchange from Backend → Supply Chain Agent → Market Analysis Agent.

## Overview

Per **SPEC Section 3.6 (User Delegated Access)** and the implementation plan in `backlog/`:

- **UI/Backend**: Users authenticate via Keycloak OIDC (existing flow).
- **Backend → Supply Chain Agent**: When the agent requires authorization, it returns `401` with a **resource token**. The backend requests an **auth token** from Keycloak; Keycloak may return a **request token** (user consent required). The backend redirects the user to Keycloak's consent page; after approval, the backend exchanges the authorization code for an **auth token** and retries with `scheme=jwt`.
- **Supply Chain Agent → Market Analysis Agent**: Market Analysis Agent can also require authorization. Supply Chain Agent receives `401` with a resource token, performs **token exchange** (SPEC §9.10) with Keycloak (presenting its upstream auth token), and retries with `scheme=jwt` and the exchanged token (including `act` claim for delegation).

## Architecture Flow

```
┌─────────┐     ┌──────────┐     ┌──────────┐     ┌─────────────┐     ┌─────────────────────┐
│  User   │     │ Backend  │     │ Keycloak │     │ Supply Chain│     │ Market Analysis     │
│ Browser │     │   API    │     │  AAuth   │     │   Agent     │     │      Agent           │
└────┬────┘     └────┬─────┘     └────┬─────┘     └──────┬──────┘     └──────────┬──────────┘
     │                │                │                   │                       │
     │ 1. Start       │                │                   │                       │
     │ optimization  │                │                   │                       │
     │───────────────►│ 2. POST (hwk/jwks)                  │                       │
     │                │──────────────────────────────────►│                       │
     │                │                │    3. 401 Agent-Auth                    │
     │                │                │       resource_token                    │
     │                │◄───────────────────────────────────│                       │
     │                │ 4. request_auth_token(resource_token)                    │
     │                │────────────────►                   │                       │
     │                │    5. request_token (consent needed) │                       │
     │                │◄────────────────                   │                       │
     │ 6. Redirect to consent_url        │                   │                       │
     │◄────────────────                  │                   │                       │
     │ 7. GET consent (session cookie)   │                   │                       │
     │────────────────►                  │                   │                       │
     │    8. Consent screen → Approve    │                   │                       │
     │◄──────────────────────────────────│                   │                       │
     │ 9. Redirect ?code=...             │                   │                   │
     │────────────────►                  │                   │                       │
     │                │ 10. exchange_code_for_token(code)   │                       │
     │                │────────────────►                   │                       │
     │                │    11. auth_token                   │                       │
     │                │◄────────────────                   │                       │
     │                │ 12. Retry POST (scheme=jwt, auth_token)                    │
     │                │──────────────────────────────────►│                       │
     │                │                │    13. 200 OK       │ 14. POST (jwks)      │
     │                │                │                   │─────────────────────►│
     │                │                │                   │ 15. 401 Agent-Auth   │
     │                │                │                   │◄─────────────────────│
     │                │                │ 16. exchange_token(upstream auth_token)   │
     │                │                │                   │────────────────►      │
     │                │                │    17. auth_token (act claim)               │
     │                │                │                   │◄────────────────      │
     │                │                │    18. Retry POST (scheme=jwt)            │
     │                │                │                   │─────────────────────►│
     │                │                │                   │    19. 200 OK         │
     │                │                │                   │◄─────────────────────│
     │                │    20. 200 OK  │                   │                       │
     │                │◄───────────────────────────────────│                       │
     │ 21. Progress / results           │                   │                       │
     │◄────────────────                 │                   │                       │
```

## Components and Behavior

### Backend

- **AAuth token service** (`backend/app/services/aauth_token_service.py`):
  - `request_auth_token(resource_token, redirect_uri)`: Calls Keycloak `agent_token_endpoint` with `request_type=auth`. Returns `auth_token` or `{ request_token, consent_required: true }`.
  - `get_consent_url(request_token, redirect_uri)`: Builds Keycloak consent URL from `agent_auth_endpoint`.
  - `exchange_code_for_token(code, redirect_uri)`: Exchanges the authorization code for `auth_token` and `refresh_token`.
- **Callback** (`backend/app/api/auth.py`): `GET /auth/aauth/callback` receives `code` and `state` (= `request_id`), exchanges code for auth token, resolves pending request, starts optimization with the new token, redirects to frontend with `?aauth_authorized=1&request_id=...` or `?aauth_error=1&...`.
- **A2A service** (`backend/app/services/a2a_service.py`): When the first call to Supply Chain Agent returns `401` with Agent-Auth, extracts `resource_token` and `auth_server`, calls token service. If response is `consent_required`, returns `{ consent_required, consent_url, request_id }` without retrying; frontend redirects user to `consent_url`.
- **Optimization API** (`backend/app/api/optimization.py`): Two-phase start when `AAUTH_AUTHORIZATION_SCHEME=user-delegated`: creates `request_id`, calls A2A once; on `consent_required`, stores pending request and returns `consent_url` and `request_id`; after user consent, callback resumes the workflow with the new auth token.
- **AAuth interceptor**: Supports `scheme=jwt`; when an auth token is available (e.g. after consent), uses it in the `Signature-Key` header for requests to Supply Chain Agent.

### Supply Chain Agent

- **Resource behavior**: When `AAUTH_AUTHORIZATION_SCHEME=autonomous` (or equivalent policy), it can require authorization. It generates a **resource token** (signed JWT binding agent, resource, scope), returns `401` with header:
  - `Agent-Auth: httpsig; auth-token; resource_token="<jwt>"; auth_server="<keycloak-issuer>"`.
- **Verification**: Verifies incoming `scheme=jwt` by validating the auth token with Keycloak JWKS (Keycloak returns JWK; the agent converts RSA JWK to PEM for PyJWT). Uses a **smart JWKS fetcher** so that `verify_signature()` can resolve both Keycloak issuer and agent `cnf.jwk`.
- **Token exchange service** (`supply-chain-agent/aauth_token_service.py`): `exchange_token(upstream_auth_token, resource_token)` POSTs to Keycloak with `request_type=exchange`, presents upstream auth token in `Signature-Key`, returns new auth token with `act` claim.
- **Interceptor**: When calling Market Analysis Agent, can send `scheme=jwks` first; if it receives `401` with Agent-Auth, it exchanges the upstream auth token for a new token and retries with `scheme=jwt`.
- **Executor**: Extracts upstream auth token from the incoming request context; on `401` from Market Analysis Agent, parses `resource_token` and `auth_server`, calls token exchange, retries with exchanged token.

### Market Analysis Agent

- **Resource behavior**: When `AAUTH_AUTHORIZATION_SCHEME=user-delegated`, requests without a valid `scheme=jwt` auth token get `401` with Agent-Auth (resource token + auth_server).
- **Resource token service** (`market-analysis-agent/resource_token_service.py`): Generates and signs resource tokens per SPEC §6 (iss, aud, agent, scope, etc.).
- **Verification**: Supports `scheme=jwt`: extracts auth token from `Signature-Key`, verifies JWT with Keycloak JWKS (with **JWK→PEM conversion** for Keycloak's RSA keys), validates `typ`, `aud`, `exp`, `agent`, `act`. Uses a **smart JWKS fetcher** for `verify_signature()` (Keycloak JWKS + `cnf.jwk`).

### Frontend (supply-chain-ui)

- On **POST /optimization/start**, if the response has `consent_required: true` and `consent_url`, the UI redirects the user to `consent_url` (Keycloak consent page).
- Keycloak redirects back to the backend callback, which then redirects to the frontend with `?aauth_authorized=1&request_id=...` (or `?aauth_error=1&...`).
- `index.js` and `useOptimization.js`: On load with `aauth_authorized=1` and `request_id`, store `request_id` (e.g. in sessionStorage) and start polling **GET /optimization/progress/{request_id}** until the optimization completes (backend has already started it after consent).

## Signature Schemes

| Scheme   | Use case                         | Header / behavior |
|----------|-----------------------------------|-------------------|
| `hwk`    | Pseudonymous, key in header       | `Signature-Key` with public key |
| `jwks`   | Identified agent, key discovery   | `Signature-Key` with `id` and `kid`; verifier fetches JWKS from agent metadata |
| `jwt`    | User-delegated (auth token)       | `Signature-Key: sig=(scheme=jwt jwt="<auth_token>")`; verifier validates JWT with Keycloak JWKS and optional `act` |

## Keycloak Integration Notes

- **Resource token**: Signed by the resource (agent); `aud` is Keycloak issuer; Keycloak validates it and may return `request_token` (consent) or directly `auth_token` (e.g. with `subject_token`).
- **Auth token**: Signed by Keycloak; contains `agent`, `cnf.jwk`, `sub` (user), `act` (delegation chain). Agents verify it using Keycloak's JWKS at `{issuer}/protocol/openid-connect/certs`; keys are JWK format — agents convert RSA JWK to PEM for PyJWT where needed.
- **Token exchange** (SPEC §9.10): Supply Chain Agent sends `request_type=exchange`, upstream auth token in `Signature-Key`, and the resource token from Market Analysis Agent; Keycloak returns a new auth token with `act` set for the delegation chain.

## See Also

- [AAuth Configuration]({{ '/aauth-configuration/' | relative_url }}) — Environment variables and Keycloak setup.
- SPEC.md — AAuth specification (Sections 3.6, 6, 9.3–9.10).
- Backlog: `backlog/user-delegated_aauth_flow_implementation_56ed9853.plan.md`, `backlog/cursor_supply_chain_agent_to_market_ana.md`, `backlog/current-status.md`.
