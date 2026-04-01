---
layout: default
title: Clarification Chat on Authorization
---

# Clarification Chat on Authorization

This document describes how the clarification chat feature is implemented in the full working demo with Keycloak and Agentgateway. This implementation demonstrates the AAuth clarification flow described in [Flow 07: Clarification Chat During Authorization](flow-07-clarification.md).

[← Back to index](index.md)

## Overview

Clarification chat allows the authorization server to ask the agent for additional context during a pending authorization request. Instead of immediately approving or denying access, the auth server can:

1. Ask a clarification question (e.g., "Why do you need access to my calendar?")
2. Receive a response from the agent
3. Present that response to the user during the consent screen
4. Complete the authorization flow with informed user consent

This demo implements clarification chat in the **backend** service, which acts as the primary agent in the demo flow and communicates with Keycloak as the authorization server.

## Implementation Architecture

```
┌─────────────────────┐         ┌──────────────┐         ┌─────────────┐
│ Supply Chain Agent  │────────▶│   Backend    │────────▶│  Keycloak   │
│                     │         │              │         │  (Auth)     │
│                     │         │ - Clarification        │             │
│                     │         │   support enabled      │ - Asks Q    │
│                     │         │ - Responds to Q        │ - Shows A   │
└─────────────────────┘         └──────────────┘         └─────────────┘
```

The backend declares `clarification_supported=True` in its AAuth metadata and implements the clarification response logic in its token service.

## Agent Configuration

### Backend Service

The backend declares clarification support in its AAuth agent metadata:

```python
# backend/app/main.py
@app.route("/.well-known/aauth-agent.json", methods=["GET"])
async def aauth_agent_metadata(request):
    agent_id_url = os.getenv("BACKEND_AGENT_ID_URL", backend_url.rstrip('/'))
    jwks_uri = f"{agent_id_url.rstrip('/')}/jwks.json"
    return JSONResponse(
        generate_agent_metadata(
            agent_id=agent_id_url,
            jwks_uri=jwks_uri,
            client_name="Supply Chain Backend",
            clarification_supported=True,  # ← Declares support
        )
    )
```

## Clarification Response Logic

The backend implements clarification handling in its token service polling logic with robust status checking and retry logic:

```python
# backend/app/services/aauth_token_service.py

AAUTH_CLARIFICATION_DEMO_RESPONSE = (
    "Great question! Honestly, we're just trying to get this demo to work. "
    "But if this were real, I'd need this access to optimize your supply chain. "
    "Please approve so we can show off the cool AAuth flow!"
)

async def _poll_pending_url(self, next_url: str, interaction_endpoint: str) -> dict:
    """Poll the pending URL until authorization completes or fails."""
    while True:
        # ... GET request to pending URL ...
        
        if response.status_code == 202:
            body = response.json() if response.content else {}
            pending_status = body.get("status")
            clarification_question = body.get("clarification")
            is_awaiting = pending_status == "awaiting_clarification"
            
            token_logger.info(
                "AAuth poll 202: body_status=%s require=%s retry_after=%s "
                "clarification=%s is_awaiting=%s",
                pending_status,
                require,
                retry_after,
                bool(clarification_question),
                is_awaiting,
            )
            
            # Handle clarification when status is "awaiting_clarification"
            if is_awaiting and clarification_question:
                post_url = body.get("location") or next_url
                token_logger.info(
                    "Clarification question from user: %s", clarification_question
                )
                token_logger.info(
                    "AAuth poll POST clarification_response url=%s (next_url was %s)",
                    post_url,
                    next_url,
                )
                
                # Send clarification response
                post_resp = await self._send_signed_json(
                    "POST",
                    post_url,
                    payload={"clarification_response": AAUTH_CLARIFICATION_DEMO_RESPONSE},
                )
                
                token_logger.info(
                    "Clarification POST result: status=%s body=%s",
                    post_resp.status_code,
                    post_resp.text[:500],
                )
                
                if post_resp.status_code in (200, 204):
                    token_logger.info("Clarification response accepted, resuming poll")
                else:
                    # Retry once on failure
                    token_logger.warning(
                        "Clarification POST unexpected status: %s — will retry once after 2s",
                        post_resp.status_code,
                    )
                    await asyncio.sleep(2)
                    post_resp2 = await self._send_signed_json(
                        "POST",
                        post_url,
                        payload={"clarification_response": AAUTH_CLARIFICATION_DEMO_RESPONSE},
                    )
                    token_logger.info(
                        "Clarification POST retry result: status=%s body=%s",
                        post_resp2.status_code,
                        post_resp2.text[:500],
                    )
                
                next_url = post_url
                continue  # Resume polling
            
            elif clarification_question and not is_awaiting:
                token_logger.warning(
                    "Clarification field present but status=%s (not awaiting_clarification) — skipping POST",
                    pending_status,
                )
```

## The Clarification Flow

### Step 1: Agent Requests Authorization

The flow begins when the backend agent requests access to a protected resource and receives a deferred authorization response:

```
Agent → Keycloak: POST /token (with resource_token)
Keycloak → Agent: 202 Accepted (with pending URL and interaction code)
```

### Step 2: Agent Polls Pending URL

The agent begins polling the pending URL. Keycloak can respond with a clarification question:

```json
{
  "status": "awaiting_clarification",
  "location": "https://keycloak.example.com/pending/a39818a6cb59",
  "require": "interaction",
  "code": "201252Z6",
  "clarification": "Why do you need access to my calendar?"
}
```

### Step 3: Agent Responds to Clarification

When the agent detects the `clarification` field and `status: "awaiting_clarification"`, it immediately POSTs a response:

```
Agent → Keycloak: POST /pending/a39818a6cb59
Content-Type: application/json
{
  "clarification_response": "This agent only requests access to fulfill the current task and uses the minimum required scope."
}
```

### Step 4: User Sees Clarification in Consent Screen

Keycloak stores the clarification response and displays it to the user during the consent interaction. The user can now make an informed decision based on:

- The requested scopes
- The agent's explanation for why it needs access
- Any additional context from the clarification exchange

### Step 5: Authorization Completes

After the user approves (or denies), the pending URL returns the final result:

```json
{
  "status": "success",
  "auth_token": "eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEi...",
  "expires_in": 3600
}
```

## Key Implementation Details

### 1. Hardcoded Demo Response

The implementation uses a hardcoded clarification response for demonstration purposes:

```python
AAUTH_CLARIFICATION_DEMO_RESPONSE = (
    "Great question! Honestly, we're just trying to get this demo to work. "
    "But if this were real, I'd need this access to optimize your supply chain. "
    "Please approve so we can show off the cool AAuth flow!"
)
```

This humorous response makes it clear this is a demo while still showing how a real agent would provide context about why it needs access.

In a production system, this would be replaced with:
- Dynamic responses based on the actual request context
- LLM-generated explanations
- Policy-driven responses based on the requested scopes
- User-configured templates

### 2. Robust Status Detection

The backend checks for BOTH the `clarification` field AND `status == "awaiting_clarification"` before sending a response. This is more robust than just checking for the presence of the clarification field, as it explicitly verifies the authorization server is waiting for a clarification response.

```python
is_awaiting = pending_status == "awaiting_clarification"
if is_awaiting and clarification_question:
    # Send clarification response
```

### 3. Retry Logic

The backend includes sophisticated retry logic for clarification POST failures. If the initial POST returns an unexpected status code, it waits 2 seconds and retries once before continuing with the polling loop. This makes the implementation more resilient to transient network issues or server errors.

### 4. Signed Requests

The backend properly signs the clarification POST request using the same AAuth signature scheme (HWK or JWKS) as the initial token request, ensuring the authorization server can verify the response came from the authenticated agent.

## Testing the Clarification Flow

To test clarification chat in this demo:

1. **Configure Keycloak** to enable clarification questions for specific clients or policies
2. **Start the backend**:
   ```bash
   cd backend
   uv run .
   ```
3. **Trigger an authorization request** that requires user consent (e.g., through the supply-chain-agent calling the backend)
4. **Watch the backend logs** for clarification question detection and response:
   ```
   INFO:aauth.tokens:Clarification question from user: Why do you need access?
   INFO:aauth.tokens:AAuth poll POST clarification_response url=...
   INFO:aauth.tokens:Clarification response accepted, resuming poll
   ```
5. **Check the Keycloak consent screen** to see the agent's clarification response displayed to the user

## Differences from Flow 07 Specification

This implementation follows the AAuth specification for clarification chat with these production-ready additions:

1. **Retry logic**: Retries failed clarification POSTs once after a 2-second delay
2. **Status checking**: Explicit `awaiting_clarification` status detection for robustness
3. **Logging**: Comprehensive logging for debugging and observability
4. **Error handling**: Graceful handling of unexpected clarification states
5. **URL extraction**: Properly extracts the POST URL from the response body's `location` field

## Benefits of Clarification Chat

1. **Informed Consent**: Users can make better authorization decisions with context
2. **Reduced Friction**: Agents can explain their needs without out-of-band communication
3. **Policy Enforcement**: Authorization servers can require explanations for sensitive scopes
4. **Audit Trail**: Clarification exchanges are logged and can be stored for compliance

## Summary

This demo implements AAuth clarification chat in the backend service, which:

- Declares `clarification_supported=True` in its AAuth metadata
- Detects clarification questions during pending authorization polling by checking for both the `clarification` field and `status == "awaiting_clarification"`
- POSTs signed clarification responses back to the pending URL
- Includes retry logic for failed POST requests
- Resumes polling after sending the response
- Handles errors and edge cases gracefully with comprehensive logging

The implementation demonstrates how clarification chat integrates seamlessly into the deferred authorization flow, providing a better user experience and more informed consent decisions in a production-ready manner.

## Related Documentation

- [Flow 07: Clarification Chat During Authorization](flow-07-clarification.md) - Specification and flow details
- [Agent Authorization (User Consent)](agent-authorization-on-behalf-of.md) - User consent flow implementation
- [Install AAuth with Keycloak](install-aauth-keycloak.md) - Setup instructions

[← Back to index](index.md)
