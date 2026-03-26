# SPEC Update Implementation Plan

## Purpose

This document is a handoff plan for updating this repo from the current `SPEC.md` implementation model to the newer `SPEC_UPDATED.md` model.

It is written for an implementation agent that will make the code changes later. No code changes are included here.

## Scope

This plan covers:

- Backend orchestration changes
- Frontend flow changes
- Supply-chain agent changes
- Market-analysis agent changes
- Metadata and challenge/header changes
- Call-chaining changes
- Validation and test strategy

This plan assumes Keycloak will be updated separately to support the new spec behavior.

## Non-Goals

This plan does not assume:

- Keycloak changes are made in this repo
- `aauth` library internals are patched here unless required
- Full production-grade persistence is added unless necessary to complete the new flow

## Critical Findings

### 1. The biggest migration is not header renaming

The biggest migration is replacing the old redirect and authorization-code flow with:

- JSON token requests
- `Prefer: wait=N`
- `202 Accepted`
- `Location` pending URLs
- `AAuth: require=interaction` or `AAuth: require=approval`
- polling on pending URLs

### 2. Backend is the main old-spec orchestration layer

Most of the old-spec logic is concentrated in:

- `backend/app/services/aauth_token_service.py`
- `backend/app/services/a2a_service.py`
- `backend/app/api/auth.py`
- `backend/app/api/optimization.py`

### 3. Agents mostly need challenge and metadata updates first

The two agents already enforce auth and issue resource tokens, but they still:

- emit `Agent-Auth` instead of `AAuth`
- use old metadata paths
- use old metadata shapes
- use old token exchange semantics in supply-chain -> market-analysis chaining

### 4. There is a repo-wide identifier compliance issue

`SPEC_UPDATED.md` requires identifiers like:

- `https://agent.example`
- lowercase
- no port
- no path
- no trailing slash

This repo currently uses many `http://localhost:port` and `http://*.localhost:3000` values. That is not spec-compliant.

The implementation agent must not silently “fix” this without an explicit strategy, because it affects:

- environment variables
- JWKS discovery
- token `iss`/`aud`
- callback URLs
- metadata

### 5. Full resource-side deferred responses are a second-phase risk

The spec now allows resources themselves to return `202` with `require=interaction`.

This repo currently depends on:

- resource `401` with challenge
- auth server deferred behavior

That means backend -> Keycloak migration is phase 1.

Resource-level interaction chaining, especially supply-chain-agent bubbling downstream market-analysis interactions back to the frontend user, should be treated as phase 2 unless required immediately.

## Implementation Strategy

Use a staged migration:

1. Introduce shared protocol helpers and response models.
2. Replace backend auth-server flow with pending/polling flow.
3. Update frontend contract to use interaction codes instead of request-token redirect URLs.
4. Update agent headers and metadata to new naming and shapes.
5. Rewrite supply-chain token exchange to use `upstream_token`.
6. Add optional resource-side deferred response support if needed.

Do not attempt a one-shot rewrite across all services at once.

## Workstream Overview

### Workstream A: Shared AAuth v2 Protocol Layer

Goal:

Create one internal protocol layer for parsing and emitting:

- `AAuth` response headers
- pending responses
- metadata document fields
- polling state transitions

Reason:

Without this, the repo will repeat string parsing and old/new header confusion in multiple places.

### Workstream B: Backend Auth Flow Rewrite

Goal:

Replace old `request_type`, redirect URI, authorization code, and refresh token behavior with:

- JSON token requests
- pending response handling
- polling
- refresh by expired `auth_token`

### Workstream C: Backend API and UI Contract Rewrite

Goal:

Replace “backend returns consent URL” with “backend returns interaction-required state”.

### Workstream D: Agent Challenge and Metadata Migration

Goal:

Make both agents emit and consume spec-updated headers and metadata.

### Workstream E: Call-Chaining Rewrite

Goal:

Change supply-chain-agent -> auth server token exchange to:

- JSON body
- `upstream_token`
- auth server `token_endpoint`
- optional deferred response support

### Workstream F: Validation and Hardening

Goal:

Add tests and runtime validation around all changed protocol behavior.

## Task Tickets

## Ticket A1: Add Shared AAuth v2 Header Parser/Emitter

### Objective

Create a shared helper module for the updated response header and pending response model.

### Files to add

- `backend/app/services/aauth_protocol.py` or similar shared backend-local helper
- Equivalent helper module for agents if cross-package sharing is not practical

### Responsibilities

Implement helpers for:

- parsing `AAuth` header values
- emitting `AAuth` header values
- representing requirement types:
  - `pseudonym`
  - `identity`
  - `auth-token`
  - `interaction`
  - `approval`
- extracting:
  - `resource-token`
  - `auth-server`
  - `code`
- validating pending response fields:
  - `status`
  - `location`
  - `require`
  - `code`

### Acceptance Criteria

- No new code uses regexes over old `Agent-Auth` strings where the new helper should be used.
- Helper supports both parsing and serialization.
- Unit tests cover each valid `require` variant.

## Ticket A2: Add Shared Deferred Response State Model

### Objective

Represent pending auth/resource flows explicitly instead of passing around raw response fragments.

### Responsibilities

Define a model that captures:

- initial request mode
- pending URL
- requirement type
- interaction code if any
- retry-after
- current terminal/non-terminal status

### Acceptance Criteria

- Backend auth flow does not rely on ad hoc dicts for pending state.
- Polling logic uses a single well-defined structure.

## Ticket B1: Rewrite Backend Metadata Discovery

### Objective

Update backend auth-server discovery from old metadata names to spec-updated names.

### Primary file

- `backend/app/services/aauth_token_service.py`

### Required changes

Replace:

- `/.well-known/aauth-issuer`
- `agent_token_endpoint`
- `agent_auth_endpoint`

With:

- `/.well-known/aauth-issuer.json`
- `token_endpoint`
- `interaction_endpoint`

### Acceptance Criteria

- Backend discovers auth-server metadata from the `.json` path.
- Backend reads `token_endpoint` and `interaction_endpoint`.
- All references to `agent_token_endpoint` and `agent_auth_endpoint` are removed from backend runtime logic.

## Ticket B2: Replace Form-Encoded Auth Requests With JSON

### Objective

Make backend token requests match `SPEC_UPDATED.md`.

### Primary file

- `backend/app/services/aauth_token_service.py`

### Required changes

Remove:

- `application/x-www-form-urlencoded`
- `request_type`
- `redirect_uri`
- `code`
- `refresh_token`

Add support for JSON bodies containing:

- `resource_token`
- `scope`
- `upstream_token`
- `auth_token`
- `purpose`
- `login_hint`
- `tenant`
- `domain_hint`

### Acceptance Criteria

- All token endpoint requests use JSON.
- No backend auth request sends `request_type`.
- No backend auth request depends on `redirect_uri` for token issuance.

## Ticket B3: Implement `202` Auth-Server Pending Flow

### Objective

Support deferred auth responses from Keycloak.

### Primary file

- `backend/app/services/aauth_token_service.py`

### Required behavior

When backend POSTs to `token_endpoint`:

- If `200`, return terminal success with `auth_token`
- If `202`, parse:
  - `Location`
  - `Retry-After`
  - `AAuth`
  - JSON body

Map response to:

- `interaction_required`
- `approval_pending`

### Acceptance Criteria

- Backend correctly distinguishes direct grant from deferred auth.
- `require=interaction` preserves interaction code and pending URL.
- `require=approval` preserves pending URL without expecting user redirect.

## Ticket B4: Implement Pending URL Polling

### Objective

Poll pending URLs until terminal response.

### Primary file

- `backend/app/services/aauth_token_service.py`

### Required behavior

Implement polling:

- `GET pending_url`
- include `Prefer: wait=N`
- signed request
- no original request body resent

Handle terminal statuses:

- `200`
- `403`
- `408`
- `410`
- `500`

Handle transient statuses:

- `202`
- `503`

### Acceptance Criteria

- Polling logic honors `Retry-After`.
- Non-202 response ends polling.
- Terminal error states are surfaced distinctly, not collapsed into generic exceptions.

## Ticket B5: Replace Refresh-Token Logic

### Objective

Remove old refresh-token assumptions and adopt refresh-by-expired-auth-token.

### Primary file

- `backend/app/services/aauth_token_service.py`

### Required changes

Remove:

- refresh token cache fields
- `refresh_auth_token(refresh_token)`
- `request_type=refresh`

Replace with:

- refresh request sending expired `auth_token` in JSON body

### Acceptance Criteria

- Backend caches only auth-token state needed for retry/refresh.
- No code path stores or expects `refresh_token`.

## Ticket C1: Replace Redirect/Code Callback Model

### Objective

Stop using the backend callback endpoint as an authorization code exchange handler.

### Primary files

- `backend/app/api/auth.py`
- `backend/app/services/optimization_service.py`
- `backend/app/api/optimization.py`

### Required changes

Current behavior:

- browser returns with `code` and `state`
- backend exchanges code for token

New behavior:

- browser returns only to wake up the app after user interaction
- backend resumes/polls the already-created pending URL

### New pending state to persist

Persist at least:

- `request_id`
- `user_id`
- original optimization request
- trace context
- pending URL
- interaction endpoint
- interaction code
- auth requirement type

### Acceptance Criteria

- Backend callback no longer expects or exchanges authorization codes.
- Backend callback can resume a pending auth flow using stored pending state.

## Ticket C2: Redesign Backend Start-Optimization API Contract

### Objective

Expose spec-updated interaction state to the frontend.

### Primary file

- `backend/app/api/optimization.py`

### New response shapes

Support at least:

- success/direct completion
- `interaction_required`
- `approval_pending`
- failure

Example backend payload for frontend:

- `request_id`
- `status`
- `interaction_endpoint`
- `interaction_code`
- `callback_url`

### Acceptance Criteria

- Backend no longer returns old consent URLs derived from request tokens.
- Backend can return interaction metadata needed for frontend redirect.

## Ticket C3: Update Frontend Interaction Flow

### Objective

Change frontend from “follow consent URL” to “construct interaction redirect”.

### Primary files

- `supply-chain-ui/src/hooks/useOptimization.js`
- `supply-chain-ui/src/index.js`
- `supply-chain-ui/src/api.js`

### Required behavior

For `interaction_required`:

- preserve current UI state
- construct redirect to:
  - `{interaction_endpoint}?code={interaction_code}&callback={callback_url}`
- navigate browser to that URL

For `approval_pending`:

- do not redirect user
- show pending state
- begin polling or resume polling via backend

### Acceptance Criteria

- Frontend no longer assumes `code`/`state` will return from Keycloak.
- Frontend no longer forwards OAuth-style callback params to backend.
- Frontend can resume after browser callback without token exchange.

## Ticket C4: Add Explicit Optimization Status States

### Objective

Represent the new spec flow in backend progress and frontend UI.

### Primary files

- `backend/app/models.py`
- `backend/app/services/optimization_service.py`
- UI state handling in `supply-chain-ui`

### Suggested states

- `pending`
- `interaction_required`
- `approval_pending`
- `authorizing`
- `running`
- `completed`
- `failed`

### Acceptance Criteria

- Progress polling can distinguish auth pending from actual agent execution.
- UI does not treat approval waiting as a failure or as a running optimization.

## Ticket D1: Rename Challenge Header and Rework Parsing

### Objective

Move all resource challenge logic from old header format to updated header format.

### Primary files

- `backend/app/services/a2a_service.py`
- `supply-chain-agent/agent_executor.py`
- `market-analysis-agent/agent_executor.py`

### Required changes

Replace:

- `Agent-Auth`
- `resource_token`
- `auth_server`

With:

- `AAuth`
- `resource-token`
- `auth-server`

Use structured format:

- `AAuth: require=auth-token; resource-token="..."; auth-server="..."`

### Acceptance Criteria

- No runtime logic depends on `Agent-Auth`.
- Backend and both agents parse and emit the updated field names.

## Ticket D2: Update Supply-Chain Agent Challenge Emission

### Objective

Update supply-chain-agent resource challenge generation to the new spec format.

### Primary files

- `supply-chain-agent/agent_executor.py`
- `supply-chain-agent/resource_token_service.py`

### Required changes

When auth is required:

- return `401`
- emit `AAuth: require=auth-token; resource-token="..."; auth-server="..."`

### Acceptance Criteria

- Backend receives updated challenge format from supply-chain-agent.
- Resource token still binds the calling agent key via `agent_jkt`.

## Ticket D3: Update Market-Analysis Agent Challenge Emission

### Objective

Update downstream agent challenge generation to the new spec format.

### Primary files

- `market-analysis-agent/agent_executor.py`
- `market-analysis-agent/resource_token_service.py`

### Acceptance Criteria

- Supply-chain-agent can parse downstream `AAuth` challenges.
- Old `Agent-Auth` output is removed.

## Ticket D4: Update Resource Token Claims

### Objective

Bring resource token payloads closer to updated spec requirements.

### Primary files

- `supply-chain-agent/resource_token_service.py`
- `market-analysis-agent/resource_token_service.py`

### Required changes

Add:

- `iat`
- `jti`

Preserve:

- `iss`
- `aud`
- `agent`
- `agent_jkt`
- `exp`
- `scope`

Optional:

- `txn`

### Acceptance Criteria

- Newly issued resource tokens contain `iat` and `jti`.
- Tokens remain verifiable by the updated Keycloak implementation.

## Ticket D5: Update Metadata Paths

### Objective

Move all metadata endpoints to `.json` well-known paths.

### Primary files

- `backend/app/main.py`
- `supply-chain-agent/__main__.py`
- `market-analysis-agent/__main__.py`

### Required changes

Add/replace:

- `/.well-known/aauth-agent.json`
- `/.well-known/aauth-resource.json`

Backend consumption should use:

- `/.well-known/aauth-issuer.json`

### Acceptance Criteria

- Old no-extension paths are no longer relied on in active runtime logic.
- New paths return JSON documents matching the updated field names.

## Ticket D6: Update Agent Metadata Shape

### Objective

Publish updated agent server metadata.

### Primary files

- `backend/app/main.py`
- `supply-chain-agent/__main__.py`
- `market-analysis-agent/__main__.py`

### Required fields

- `agent`
- `jwks_uri`
- `client_name`

Optional fields to include where relevant:

- `callback_endpoint`
- `logo_uri`
- `logo_dark_uri`
- `localhost_callback_allowed`
- `clarification_supported`

### Acceptance Criteria

- Backend agent metadata includes callback support if frontend/browser return is still used.
- Supply-chain and market-analysis agents publish agent metadata suitable for downstream verification.

## Ticket D7: Update Resource Metadata Shape

### Objective

Publish updated resource metadata.

### Primary files

- `supply-chain-agent/__main__.py`
- `market-analysis-agent/__main__.py`

### Required fields

- `resource`
- `jwks_uri`

Optional fields

- `resource_token_endpoint`
- `interaction_endpoint`
- `client_name`
- `logo_uri`
- `logo_dark_uri`
- `additional_signature_components`

### Acceptance Criteria

- Resource metadata uses updated field names.
- If proactive resource token support is deferred, omit `resource_token_endpoint` instead of inventing one.

## Ticket E1: Rewrite Supply-Chain Token Exchange to `upstream_token`

### Objective

Bring downstream token exchange in line with the new spec.

### Primary files

- `supply-chain-agent/aauth_token_service.py`
- `supply-chain-agent/agent_executor.py`

### Required changes

Remove:

- `request_type=exchange`
- upstream auth token carried via `Signature-Key`
- form-encoded exchange body

Replace with:

- JSON body containing:
  - `resource_token`
  - `upstream_token`
- request signed with the supply-chain agent’s own key
- auth-server metadata discovery using `token_endpoint`

### Acceptance Criteria

- Downstream exchange no longer relies on old exchange semantics.
- Market-analysis access works when Keycloak issues direct grant tokens.

## Ticket E2: Handle Deferred Responses During Downstream Exchange

### Objective

Allow downstream auth-server interaction/approval to be represented instead of collapsing into a generic error.

### Primary files

- `supply-chain-agent/aauth_token_service.py`
- `supply-chain-agent/agent_executor.py`

### Required behavior

If downstream auth returns:

- `202` + `require=approval`, preserve pending state
- `202` + `require=interaction`, bubble this up in a structured way

### Acceptance Criteria

- Supply-chain-agent does not reduce deferred downstream auth to `"No market analysis provided"`.
- Deferred downstream auth can be surfaced to callers or explicitly deferred to phase 2.

## Ticket E3: Decide Whether To Implement Resource-Level `202` Support Now

### Objective

Make an explicit decision on phase scope.

### Options

Option 1:

- Phase 1 supports only resource `401` + auth-server `202`
- No resource-issued `202` pending responses yet

Option 2:

- Phase 1 also implements resource-issued `202` interaction flows

### Recommendation

Choose Option 1 first unless full interaction chaining from market-analysis-agent is a hard requirement.

### Acceptance Criteria

- Decision is documented in code comments or backlog notes.
- No half-implemented resource `202` behavior is left in place.

## Ticket F1: Introduce Test Coverage for New Header and Polling Logic

### Objective

Prevent regressions while refactoring the most fragile path.

### Suggested test areas

- `AAuth` parser/serializer
- pending response parser
- token endpoint `200` path
- token endpoint `202 interaction` path
- token endpoint `202 approval` path
- polling terminal responses
- refresh-by-expired-token request construction

### Acceptance Criteria

- Tests exist for each core pending-state path.
- Old `request_type` behavior is not silently reintroduced.

## Ticket F2: Add Integration Tests for Backend Optimization Flow

### Objective

Validate the backend API contract end-to-end.

### Suggested cases

- optimization direct grant
- optimization interaction required
- optimization approval pending
- optimization resume after callback
- optimization failure on expired/denied pending URL

### Acceptance Criteria

- Backend start endpoint and progress endpoint reflect the new state machine.

## Ticket F3: Add Metadata Contract Tests

### Objective

Make sure metadata changes stay aligned with the updated spec.

### Suggested coverage

- `.well-known/aauth-agent.json`
- `.well-known/aauth-resource.json`
- field names and required values

### Acceptance Criteria

- No code path relies on old well-known paths without test coverage explicitly documenting compatibility.

## File-by-File Change Map

## Backend

### `backend/app/services/aauth_token_service.py`

Rewrite heavily.

Remove:

- request token flow
- code exchange flow
- refresh token flow
- old metadata discovery names
- form encoding

Add:

- JSON request modes
- pending response handling
- polling
- refresh-by-expired-auth-token

### `backend/app/services/a2a_service.py`

Refactor heavily.

Replace:

- old `Agent-Auth` parsing
- old consent URL assumptions

Add:

- new `AAuth` parsing
- interaction/approval result propagation
- cleaner response classification

### `backend/app/api/auth.py`

Refactor.

Replace code exchange callback logic with callback/resume logic.

### `backend/app/api/optimization.py`

Refactor.

Return structured pending states and support resumed workflows.

### `backend/app/services/optimization_service.py`

Refactor pending state storage.

Persist enough data to resume pending polling flows.

### `backend/app/models.py`

Update optimization status modeling and possibly API response models.

### `backend/app/main.py`

Update metadata endpoint paths and payload shapes.

## Supply-Chain Agent

### `supply-chain-agent/agent_executor.py`

Refactor both:

- inbound auth enforcement/challenge logic
- downstream market-analysis chaining behavior

### `supply-chain-agent/aauth_token_service.py`

Rewrite token exchange semantics.

### `supply-chain-agent/resource_token_service.py`

Update token claims.

### `supply-chain-agent/__main__.py`

Update metadata paths and shapes.

## Market-Analysis Agent

### `market-analysis-agent/agent_executor.py`

Refactor challenge emission and preserve future option for resource-level `202`.

### `market-analysis-agent/resource_token_service.py`

Update token claims.

### `market-analysis-agent/__main__.py`

Update metadata paths and shapes.

## Frontend

### `supply-chain-ui/src/hooks/useOptimization.js`

Refactor interaction handling and resume logic.

### `supply-chain-ui/src/index.js`

Remove assumptions about auth-server returning OAuth-style `code` and `state`.

### `supply-chain-ui/src/api.js`

Likely small changes only, depending on backend response contract.

## Recommended Execution Order

1. Implement shared header/pending models.
2. Rewrite backend token client.
3. Update backend optimization API contract.
4. Update frontend interaction flow.
5. Update supply-chain-agent challenge/header behavior.
6. Update market-analysis-agent challenge/header behavior.
7. Update metadata endpoints and payloads everywhere.
8. Rewrite downstream token exchange.
9. Add tests and validate staged flows.
10. Decide on and optionally implement resource-level `202` support.

## Risks and Open Decisions

## Risk 1: `aauth` library compatibility

The repo depends on `aauth>=0.1.0` for:

- request signing
- signature verification
- JWKS generation

The implementation agent must verify early whether the installed version is compatible with:

- updated signature label/header conventions
- any structured-field formatting assumptions

If not, choose one:

- upgrade dependency
- add local compatibility layer
- temporarily normalize locally around library limitations

## Risk 2: A2A SDK handling of `202`

If A2A client/server layers do not expose `202 + Location + AAuth` cleanly, backend-only auth-server deferral can still proceed, but resource-level deferral will need extra integration work.

## Risk 3: Identifier compliance

Before attempting strict spec compliance, decide:

- keep local demo `http://localhost` style values for development compatibility
- or introduce proper HTTPS fronting and spec-compliant origin identifiers

This should be decided before broad metadata/token changes land.

## Risk 4: Callback semantics

The updated spec reduces callback importance to UX only. The implementation should not recreate old security assumptions around callback URLs.

## Acceptance Definition For The Overall Migration

The migration is complete when:

- backend no longer uses `request_type`, authorization codes, or refresh tokens
- backend discovers auth server metadata via `/.well-known/aauth-issuer.json`
- backend can handle `200`, `202 interaction`, and `202 approval` from auth server
- frontend redirects using interaction code plus callback URL
- backend resumes/polls after callback without code exchange
- agents emit `AAuth` instead of `Agent-Auth`
- agents publish `.json` metadata endpoints with updated field names
- supply-chain-agent token exchange uses JSON `upstream_token`
- tests cover the new flow

## Recommended Phase Split

## Phase 1

Implement:

- updated backend auth-server flow
- updated frontend interaction flow
- updated `AAuth` challenge format
- updated metadata endpoints
- updated downstream token exchange direct-grant path

Do not implement yet:

- full resource-issued `202` interaction chaining
- clarification chat
- proactive `resource_token_endpoint` unless needed

## Phase 2

Implement if required:

- resource-issued `202` pending flows
- chained interaction bubbling
- clarification chat
- proactive resource token acquisition
- stricter identifier compliance infrastructure

## Short Implementation Brief For The Agent

Start with the backend. Replace old auth orchestration with a pending/polling model before touching the UI or downstream chaining. Then update the frontend to redirect using interaction code and callback URL. After that, migrate both agents to new header and metadata formats. Finally, rewrite supply-chain token exchange to use `upstream_token`, and only then evaluate whether full resource-level deferred responses are necessary for this demo.
