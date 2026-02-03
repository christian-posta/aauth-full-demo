---
layout: default
title: AAuth Configuration Reference
---

# AAuth Configuration Reference

This document lists environment variables and Keycloak setup for AAuth (including user-delegated flow, resource tokens, and token exchange). Copy each component's `env.example` to `.env` and adjust values.

---

## Backend

| Variable | Description | Example |
|----------|-------------|---------|
| `AAUTH_SIGNATURE_SCHEME` | Outgoing signature scheme: `hwk`, `jwks`, or `jwt` (when auth token is available). | `hwk` or `jwks` |
| `BACKEND_AGENT_URL` | Agent identifier for JWKS scheme; used in `Signature-Key` and key discovery. | `http://backend.localhost:8000` |
| `AAUTH_CALLBACK_URL` | Redirect URI for Keycloak consent callback. Must match what is sent to Keycloak. Default: `{BACKEND_AGENT_URL}/auth/aauth/callback`. | `http://backend.localhost:8000/auth/aauth/callback` |
| `AAUTH_FRONTEND_REDIRECT_URL` | Where to send the user after consent (frontend URL). Default: `http://localhost:3050`. | `http://localhost:3050` |
| `KEYCLOAK_URL` | Keycloak base URL. | `http://localhost:8080` |
| `KEYCLOAK_REALM` | Keycloak realm. | `aauth-test` |
| `KEYCLOAK_AAUTH_ISSUER_URL` | AAuth issuer URL; used for metadata and token endpoints. Default: `{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}`. | `http://localhost:8080/realms/aauth-test` |
| `KEYCLOAK_AAUTH_AGENT_TOKEN_ENDPOINT` | Optional; agent token endpoint. If unset, derived from issuer metadata. | — |
| `KEYCLOAK_AAUTH_AGENT_AUTH_ENDPOINT` | Optional; consent (agent auth) URL. If unset, from issuer metadata. | — |
| `AAUTH_AUTH_TOKEN_CACHE_TTL` | Auth token cache TTL in seconds. | `3600` |

**User-delegated flow:** Set `AAUTH_CALLBACK_URL` and `AAUTH_FRONTEND_REDIRECT_URL` so that after consent Keycloak redirects to the backend callback, and the backend then redirects the user to the UI. Ensure the frontend runs on the host/port used in `AAUTH_FRONTEND_REDIRECT_URL` (e.g. port 3050 if that's where the UI is served).

---

## Supply Chain Agent

| Variable | Description | Example |
|----------|-------------|---------|
| `AAUTH_SIGNATURE_SCHEME` | Outgoing scheme to downstream (Market Analysis Agent): `hwk` or `jwks`. | `jwks` |
| `SUPPLY_CHAIN_AGENT_ID_URL` | Agent identifier; used in `Signature-Key` and as resource issuer for resource tokens. | `http://supply-chain-agent.localhost:3000` |
| `SUPPLY_CHAIN_AGENT_URL` | Local listen URL (optional override). | `http://localhost:9999/` |
| `AAUTH_AUTHORIZATION_SCHEME` | `autonomous` (require scheme=jwt with valid auth_token) or `user-delegated` (same, but name aligns with consent flow). | `autonomous` |
| `AAUTH_RESOURCE_ADDITIONAL_SCOPES` | Optional; extra scopes on resource tokens (space-separated). | — |
| `KEYCLOAK_AAUTH_ISSUER_URL` | Keycloak AAuth issuer; used to verify auth tokens and perform token exchange. | `http://localhost:8080/realms/aauth-test` |
| `KEYCLOAK_AAUTH_AGENT_TOKEN_ENDPOINT` | Optional; agent token endpoint for exchange. | — |
| `KEYCLOAK_URL`, `KEYCLOAK_REALM` | Fallback if `KEYCLOAK_AAUTH_ISSUER_URL` is not set. | `http://localhost:8080`, `aauth-test` |
| `MARKET_ANALYSIS_AGENT_URL` | Market Analysis Agent base URL for downstream calls. | `http://market-analysis-agent.localhost:3000/` |

**Token exchange:** When Market Analysis Agent returns 401 with Agent-Auth, the Supply Chain Agent uses `KEYCLOAK_AAUTH_ISSUER_URL` (and optional `KEYCLOAK_AAUTH_AGENT_TOKEN_ENDPOINT`) to call the agent token endpoint with `request_type=exchange`, presenting the upstream auth token and the resource token from the 401 response.

---

## Market Analysis Agent

| Variable | Description | Example |
|----------|-------------|---------|
| `AAUTH_SIGNATURE_SCHEME` | Signature scheme expected from callers: `hwk` or `jwks`. (Verification also supports `jwt` when auth token is present.) | `jwks` |
| `MARKET_ANALYSIS_AGENT_ID_URL` | Agent/resource identifier; used for `aud` in auth token verification and as resource issuer for resource tokens. | `http://market-analysis-agent.localhost:3000` |
| `MARKET_ANALYSIS_AGENT_URL` | Local listen URL (optional override). | `http://localhost:9998/` |
| `AAUTH_AUTHORIZATION_SCHEME` | `autonomous` or `user-delegated`. When `user-delegated`, requests without a valid `scheme=jwt` auth token receive 401 with Agent-Auth (resource_token + auth_server). | `user-delegated` |
| `KEYCLOAK_AAUTH_ISSUER_URL` | Keycloak AAuth issuer; used to verify auth tokens (JWKS at `{issuer}/protocol/openid-connect/certs`). | `http://localhost:8080/realms/aauth-test` |
| `KEYCLOAK_URL`, `KEYCLOAK_REALM` | Fallback if `KEYCLOAK_AAUTH_ISSUER_URL` is not set. | `http://localhost:8080`, `aauth-test` |
| `AAUTH_RELAX_CONTENT_DIGEST` | Optional; set to `true` to relax content-digest verification if the signer omits it. Default: `false`. | — |

**JWT verification:** Keycloak's JWKS is in JWK format; the agent converts RSA JWK to PEM for PyJWT. For `scheme=jwt`, the agent also provides a JWKS fetcher to the AAuth library so that both Keycloak issuer and token `cnf.jwk` can be resolved.

---

## Frontend (supply-chain-ui)

| Variable | Description | Example |
|----------|-------------|---------|
| `REACT_APP_KEYCLOAK_URL` | Keycloak base URL for OIDC. | `http://localhost:8080` |
| `REACT_APP_KEYCLOAK_REALM` | Keycloak realm. | `mcp-realm` or `aauth-test` |
| `REACT_APP_KEYCLOAK_CLIENT_ID` | Keycloak client ID for the UI. | `supply-chain-ui` |
| `REACT_APP_API_BASE_URL` | Backend API base URL. | `http://localhost:8000` |

No AAuth-specific env vars are required in the UI. Consent flow is driven by backend responses (`consent_required`, `consent_url`, `request_id`) and redirect query params (`aauth_authorized`, `request_id`, `aauth_error`).

---

## Keycloak Setup (summary)

1. **Realm**: e.g. `aauth-test`.
2. **OIDC client**: For the UI (e.g. `supply-chain-ui`), public client, standard flow, valid redirect URIs for the frontend.
3. **AAuth / Agent Auth**: Configure AAuth issuer metadata and agent token endpoint so that:
   - Backend and agents can discover `agent_token_endpoint` and `agent_auth_endpoint` (e.g. from `/.well-known/aauth-issuer` or equivalent).
   - Resource tokens issued by Supply Chain Agent and Market Analysis Agent are validated by Keycloak (issuer/audience/agent/scope).
   - Consent flow uses `agent_auth_endpoint`; after login/consent, Keycloak redirects to `redirect_uri` with an authorization code that the backend exchanges for an auth token.

4. **JWKS**: Auth tokens are signed by Keycloak; agents verify them using Keycloak's JWKS at:
   - `{KEYCLOAK_AAUTH_ISSUER_URL}/protocol/openid-connect/certs`
   Keys are in JWK format; agents that use PyJWT convert RSA JWK to PEM for verification.

---

## Hostnames and Ports

For signature verification, agents use **canonical authority** derived from their agent ID URL (e.g. `supply-chain-agent.localhost:3000`). Ensure:

- `/etc/hosts` (or equivalent) maps:
  - `backend.localhost` → `127.0.0.1`
  - `supply-chain-agent.localhost` → `127.0.0.1`
  - `market-analysis-agent.localhost` → `127.0.0.1`
- Backend and UI are reachable at the URLs used in redirect_uri and frontend redirect (e.g. backend on 8000, UI on 3000 or 3050).

---

## See Also

- [User-Delegated AAuth Flow](user-delegated-aauth.md)
- Component `env.example` files: `backend/env.example`, `supply-chain-agent/env.example`, `market-analysis-agent/env.example`, `supply-chain-ui/env.example`
