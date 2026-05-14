---
layout: default
title: Agent Authorization (Autonomous)
nav_order: 3
---

# Agent Authorization (Autonomous)

Mode 3 requires the resource to issue a 401 challenge when an agent presents only its `aa-agent+jwt`. The agent extracts the `aa-resource+jwt` from the `AAuth` response header, exchanges it at the Person Server for an `aa-auth+jwt` auth token, then retries the request. This is the [PS-Managed (3-Party) flow](https://explorer.aauth.dev/access/ps-managed) in the AAuth spec.

[← Back to index](index.md)

## Watch the demo

<div style="position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden; max-width: 100%; margin: 1em 0;">
  <iframe style="position: absolute; top: 0; left: 0; width: 100%; height: 100%;" src="https://www.youtube.com/embed/yodHMGStNNA" title="Agent Authorization (Autonomous) Demo" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>
</div>

## Run the components

To run this demo, [please set up the prerequisites](./install-aauth-keycloak.md) (Keycloak, Person Server, Agentgateway).


### Start the Infrastructure (Mode 3)

Use the infrastructure script to start everything with the auth-token config:

```bash
./scripts/start-infra.sh mode3
```

This starts agentgateway with `config-policy.yaml` and the aauth-service with `aauth-config-mode3.yaml`, which configures the supply-chain-agent resource to require `auth-token`. All agents bootstrap their `aa-agent+jwt` automatically from the Person Server on startup — no manual key or scheme flags needed.

At this point you're ready to return to the UI to review the demo flow:

## Walking through the Demo Flow

From the main UI page, if you click the `"Optimize Laptop Supply Chain"` button, it should kick off the flow for the backend components. You may need to refresh the page (some time the OIDC token / User session expires). if it fails, try restarting the `agentgateway` as that can cache JWKS and become stale. 

The flow we see will look like this:

```mermaid
sequenceDiagram
  participant UI as UI
  participant BE as Backend
  participant SCA as Supply-Chain Agent

  UI->>BE: 1. User clicks "Optimize Laptop Supply Chain"
  BE->>SCA: 2. POST /optimize (with agent identity JWT/JWS)
  SCA-->>BE: 3. 401 Unauthorized, returns Resource Token
  BE->>SCA: 4. Retry POST /optimize with Resource Token (auth_token)
  SCA-->>BE: 5. Response: Optimization in progress/result
  BE-->>UI: 6. Return progress/result to user
```

When `backend` calls `supply-chain-agent`, it receives a 401 and an `AAuth` response header carrying the resource token. The resource token binds the requested scopes to the calling agent (`backend`). Backend logs:

```bash
INFO:aauth_interceptor:🔐 AAuth: Signing with agent token (aa-agent+jwt in Signature-Key)
INFO:aauth_interceptor:🔐 SIGNING with: method=POST, target_uri='http://supply-chain-agent.localhost:3000/'
INFO:aauth.tokens:🔐 401 from supply-chain-agent (url=http://supply-chain-agent.localhost:3000): headers={'date': 'Fri, 06 Feb 2026 22:12:49 GMT', 'server': 'uvicorn', 'aauth': 'require=auth-token; resource-token="eyJhbGciOiJFZERTQSIsImtpZCI6InN1cHBseS1jaGFpbi1hZ2VudC1lcGhlbWVyYWwtMSIsInR5cCI6InJlc291cmNlK2p3dCJ9.eyJpc3MiOiJodHRwOi8vc3VwcGx5LWNoYWluLWFnZW50LmxvY2FsaG9zdDozMDAwIiwiYXVkIjoiaHR0cDovLzEyNy4wLjAuMTo4NzY1IiwiYWdlbnQiOiJodHRwOi8vYmFja2VuZC5sb2NhbGhvc3Q6ODAwMCIsImFnZW50X2prdCI6Il9YUHA3YmZNdDV1Z25yUnFBU1VuS2JaRW5rd2JrRmpwb01GQS1lemVYS3ciLCJleHAiOjE3NzA0MTYyNzAsInNjb3BlIjoic3VwcGx5LWNoYWluOm9wdGltaXplIn0.ZAUQNnQz76zSbp4XGRyST_K5b0wVavVys5sYIUKJwLWe6LnJqN6By-37jdXDuup5c9nGak3iXw1MlaqAIdkgDQ"; auth-server="http://127.0.0.1:8765"', 'content-length': '22', 'content-type': 'text/plain; charset=utf-8'}
```
{: .log-output}

Here we can see that we got a `401` when `backend` tried to call `supply-chain-agent` and it also returned an `AAuth` header with `require=auth-token` and a resource token. This resource token binds a request for scopes to call this `supply-chain-agent` to the `backend` caller. The `auth-server` in the response is the **Person Server** (`http://127.0.0.1:8765`), which is also the AAuth Agent Provider that issued the agents' `aa-agent+jwt` tokens. If we decode the JWT resource token it looks like this:

```json
{
  "iss": "http://supply-chain-agent.localhost:3000",
  "aud": "http://127.0.0.1:8765",
  "agent": "http://backend.localhost:8000",
  "agent_jkt": "_XPp7bfMt5ugnrRqASUnKbZEnkwbkFjpoMFA-ezeXKw",
  "exp": 1770416270,
  "scope": "supply-chain:optimize"
}
```

This token proves that `backend` was trying to call `supply-chain-agent` with the listed scopes. The `aud` is the **Person Server** (`http://127.0.0.1:8765`) — the same entity that issued the agents' `aa-agent+jwt` tokens and that will exchange this resource token for an `aa-auth+jwt`.

The aauth-service at the gateway side (on behalf of supply-chain-agent) verified the incoming request by:
1. Decoding the `aa-agent+jwt` from the `Signature-Key` header
2. Fetching the AAuth Agent Provider JWKS at `{iss}/.well-known/aauth-agent.json` to verify the JWT signature
3. Verifying `cnf.jwk` matches the key that signed the HTTP request (proof-of-possession)
4. Finding that `access: require: auth-token` is configured — issuing a 401 resource-token challenge

Further in the logs, you can see the `supply-chain-agent` (via aauth-service) creates a Resource token and responds with `HTTP 401`:


```bash
INFO:resource_token_service:✅ Resource token generated successfully
INFO:aauth.tokens:🔐 Issuing resource_token: eyJhbGciOiJFZERTQSIsImtpZCI6InN1cHBseS1jaGFpbi1hZ2VudC1lcGhlbWVyYWwtMSIsInR5cCI6InJlc291cmNlK2p3dCJ9.eyJpc3MiOiJodHRwOi8vc3VwcGx5LWNoYWluLWFnZW50LmxvY2FsaG9zdDozMDAwIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9hYXV0aC10ZXN0IiwiYWdlbnQiOiJodHRwOi8vYmFja2VuZC5sb2NhbGhvc3Q6ODAwMCIsImFnZW50X2prdCI6Il9YUHA3YmZNdDV1Z25yUnFBU1VuS2JaRW5rd2JrRmpwb01GQS1lemVYS3ciLCJleHAiOjE3NzA0MTYyNzAsInNjb3BlIjoic3VwcGx5LWNoYWluOm9wdGltaXplIn0.ZAUQNnQz76zSbp4XGRyST_K5b0wVavVys5sYIUKJwLWe6LnJqN6By-37jdXDuup5c9nGak3iXw1MlaqAIdkgDQ
INFO:agent_executor:🔐 Issuing resource_token for agent: http://backend.localhost:8000
INFO:agent_executor:🔐 401 AAuth challenge: returning resource_token in AAuth response header
```
{: .log-output}

When the `backend` has the resource token, it presents its `aa-agent+jwt` (with `scheme=jwt` in the `Signature-Key`) to the Person Server token endpoint and requests an auth token:

```bash
INFO:aauth.tokens:🔐 Received auth_token from auth server: eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiYXV0aCtqd3QiLCJraWQiIDogIjF2SGZlTWk5U0E4VTdWZlNKRTN3SnVTQklOZUhVeWpOY0pzZ2tYWWNHQlkifQ.eyJleHAiOjE3NzA0MTYyNzAsImlhdCI6MTc3MDQxNTk3MCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9hYXV0aC10ZXN0IiwiYXVkIjoiaHR0cDovL3N1cHBseS1jaGFpbi1hZ2VudC5sb2NhbGhvc3Q6MzAwMCIsImFnZW50IjoiaHR0cDovL2JhY2tlbmQubG9jYWxob3N0OjgwMDAiLCJjbmYiOnsiandrIjp7ImtpZCI6IjFpUHZER1dzcHJYcWpSY2ZlSGtsRThWVmpEY0xKWndkZTEycW1xemN2RjAiLCJrdHkiOiJPS1AiLCJ1c2UiOiJzaWciLCJjcnYiOiJFZDI1NTE5IiwieCI6IjE3YjFaWjFhVlJSZ1VjcVA0UE94TG5mMThoa0lqU2N5T1p5NXVQX3MzUTAifX0sInNjb3BlIjoic3VwcGx5LWNoYWluOm9wdGltaXplIn0.QAcEFcaW46-TNCVEn5u5uFC-_9nXP7bFE__EkbG7gvKO66xWePUfOJALRJ7G68JX45iZNRrtm4gNTH9axWNWkoWBPTkauR8fMdX-3Hh6BcM0lKC7vBH6iLIws7hWM0d3Cmwwd3QdIkiOhydbeka3IZ0MzUi5p-PUiZp7siGLONfG2D7mbhaf00t3QNrabdaNwMd3kUniqpm3nUhb-j7d2vruxuX6cPHvIdWS6B3x3dprCH71wb97-js6IVgBsew2XLh15_BeAykA4iM_jp4YF3Rpy9hDB3SzFRN8S6frenLkAh3TRnk4Ii5fXMJEyGwuduQmP7oxn_xW4kzJvdLYVw
INFO:     127.0.0.1:55603 - "POST /optimization/start HTTP/1.1" 200 OK
INFO:     127.0.0.1:55603 - "OPTIONS /optimization/progress/5cb9b75d-b160-4142-8042-0ffa47b7a2de HTTP/1.1" 200 OK
INFO:     127.0.0.1:55603 - "GET /optimization/progress/5cb9b75d-b160-4142-8042-0ffa47b7a2de HTTP/1.1" 200 OK
```
{: .log-output}

The Person Server has issued us an `aa-auth+jwt` auth token! Let's decode that token:

```json
{
  "exp": 1770416270,
  "iat": 1770415970,
  "iss": "http://127.0.0.1:8765",
  "aud": "http://supply-chain-agent.localhost:3000",
  "agent": "http://backend.localhost:8000",
  "cnf": {
    "jwk": {
      "kid": "1iPvDGWsprXqjRcfeHklE8VVjDcLJZwde12qmqzcvF0",
      "kty": "OKP",
      "use": "sig",
      "crv": "Ed25519",
      "x": "17b1ZZ1aVRRgUcqP4POxLnf18hkIjScyOZy5uP_s3Q0"
    }
  },
  "scope": "supply-chain:optimize"
}
```

The key parts of this token (`aa-auth+jwt`, AAuth spec §9.4.1):

* **`iss`** — the Person Server that issued this auth token (same entity that issued the `aa-agent+jwt` tokens)
* **`aud`** — this token is scoped to the `supply-chain-agent` and is useless anywhere else
* **`agent`** — the verified identity of the caller (matched the `agent` claim from the resource token)
* **`cnf.jwk`** — pinned to the backend's **current ephemeral public key**; only the backend can use this token because only the backend holds the matching private key

The `backend` now presents this `aa-auth+jwt` in the `Signature-Key` header, signs the request with its ephemeral key, and retries. The aauth-service verifies the token and proof-of-possession, then forwards the request.

Now when `supply-chain-agent` gets this request, with the right scheme and authorization token, it will allow the call to proceed successfully and return a result:

```bash

INFO:agent_executor:✅ AAuth signature verification successful
INFO:aauth.tokens:🔐 Received auth_token in request (HTTPSig scheme=jwt): eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiYXV0aCtqd3QiLCJraWQiIDogIjF2SGZlTWk5U0E4VTdWZlNKRTN3SnVTQklOZUhVeWpOY0pzZ2tYWWNHQlkifQ.eyJleHAiOjE3NzA0MTYyNzAsImlhdCI6MTc3MDQxNTk3MCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9hYXV0aC10ZXN0IiwiYXVkIjoiaHR0cDovL3N1cHBseS1jaGFpbi1hZ2VudC5sb2NhbGhvc3Q6MzAwMCIsImFnZW50IjoiaHR0cDovL2JhY2tlbmQubG9jYWxob3N0OjgwMDAiLCJjbmYiOnsiandrIjp7ImtpZCI6IjFpUHZER1dzcHJYcWpSY2ZlSGtsRThWVmpEY0xKWndkZTEycW1xemN2RjAiLCJrdHkiOiJPS1AiLCJ1c2UiOiJzaWciLCJjcnYiOiJFZDI1NTE5IiwieCI6IjE3YjFaWjFhVlJSZ1VjcVA0UE94TG5mMThoa0lqU2N5T1p5NXVQX3MzUTAifX0sInNjb3BlIjoic3VwcGx5LWNoYWluOm9wdGltaXplIn0.QAcEFcaW46-TNCVEn5u5uFC-_9nXP7bFE__EkbG7gvKO66xWePUfOJALRJ7G68JX45iZNRrtm4gNTH9axWNWkoWBPTkauR8fMdX-3Hh6BcM0lKC7vBH6iLIws7hWM0d3Cmwwd3QdIkiOhydbeka3IZ0MzUi5p-PUiZp7siGLONfG2D7mbhaf00t3QNrabdaNwMd3kUniqpm3nUhb-j7d2vruxuX6cPHvIdWS6B3x3dprCH71wb97-js6IVgBsew2XLh15_BeAykA4iM_jp4YF3Rpy9hDB3SzFRN8S6frenLkAh3TRnk4Ii5fXMJEyGwuduQmP7oxn_xW4kzJvdLYVw
INFO:agent_executor:🔐 Auth token detected in request (scheme=jwt)
INFO:httpx:HTTP Request: GET http://localhost:8080/realms/aauth-test/protocol/openid-connect/certs "HTTP/1.1 200 OK"
INFO:agent_executor:✅ Auth token verified successfully
INFO:agent_executor:✅ Authorization successful: auth_token verified for agent: http://backend.localhost:8000
INFO:agent_executor:🔐 Extracted upstream auth_token for token exchange (length: 945)
INFO:agent_executor:🔐 Using AAuth JWKS_URI signing for downstream agent calls
INFO:agent_executor:🔐 Upstream auth_token available for token exchange if needed
INFO:     127.0.0.1:55606 - "POST / HTTP/1.1" 200 OK
```
{: .log-output}

> **Note on "JWKS_URI signing":** This internal log label is the implementation's name for the `aa-agent+jwt` JWT scheme. The agent presents its `aa-agent+jwt` in the `Signature-Key` header (not a JWKS URL); the gateway verifies the embedded `cnf.jwk` proof-of-possession signature. No external JWKS endpoint is fetched for the agent itself.

## Tracing from Jaeger (Optional):

The components in this demo all participate in distributed tracing with Jaeger. We can see these same characteristics of the AAuth flow in Jaeger. With Jaeger running, navigate to `http://localhost:16686`. If you click on `supply-chain-backend` and then "Find Traces" you'll see some of the recent traces:

![](./images/jaeger-1.png)


If you click a trace`optimization_api.start_optimization` you'll see the full flow. This will show the first call from `backend` to `supply-chain-agent` that fails, and how the `supply-chain-agent` responds. 


![](./images/jaeger-2.png)


But if you look closer at the request (scroll down to see headers), you'll see that the request was signed with JWKS and that the `supply-chain-agent` responded with a Resource token. 



![](./images/jaeger-3.png)

If you scroll farther down, you'll see the call eventually succeeds with a valid JWT authorization token. 

![](./images/jaeger-4.png)


## Summary: Authorization Flow Diagram

```mermaid
flowchart LR
    BE[Backend] -->|1. Signed request| AGW[Agentgateway] --> SCA[Supply-Chain Agent]
    SCA -->|2. 401 + resource_token| BE
    BE -->|3. Exchange for auth_token| PS[Person Server :8765]
    PS -->|4. aa-auth+jwt| BE
    BE -->|5. Retry with auth_token| AGW --> SCA
```

**Key:** Supply-Chain Agent challenges with resource_token → Backend exchanges it at the Person Server for `aa-auth+jwt` → Retry succeeds with JWT authorization.

---

## Automated Testing (Mode 3)

The autonomous auth-token flow is exercised by the **mode3** test suite. Start the infrastructure with the policy-enabled config and run the tests:

```bash
# Requires Keycloak and Person Server already running
./scripts/start-infra.sh mode3
./scripts/run-tests.sh mode3
./scripts/stop-infra.sh
```

Mode 3 uses `agentgateway/config-policy.yaml` and `agentgateway/aauth-config-mode3.yaml`. The agentgateway actively validates AAuth auth-tokens and applies CEL authorization rules before forwarding agent requests to the supply-chain-agent.

### What the Tests Verify

`tests/integration/test_mode3_flow.py` contains six tests:

| Test | What it checks |
|------|---------------|
| `test_mode3_optimization_flow` | Full start → poll → results with auth-token exchange |
| `test_mode3_market_analysis` | `"perform market analysis"` triggers SCA → MAA call with auth-token |
| `test_mode3_invalid_token_rejected` | `Authorization: Bearer invalid-token` returns 401/403 at the backend |
| `test_mode3_no_auth_header_rejected` | Missing `Authorization` header returns 401/403 |
| `test_mode3_agent_health` | Supply-chain-agent `.well-known` endpoint is reachable |
| `test_mode3_extended_flow` | `"supply chain analysis with market insights"` exercises the SCA→MAA agent-to-agent path |

### Expected Output

```
tests/integration/test_mode3_flow.py::test_mode3_optimization_flow PASSED
tests/integration/test_mode3_flow.py::test_mode3_market_analysis PASSED
tests/integration/test_mode3_flow.py::test_mode3_invalid_token_rejected PASSED
tests/integration/test_mode3_flow.py::test_mode3_no_auth_header_rejected PASSED
tests/integration/test_mode3_flow.py::test_mode3_agent_health PASSED
tests/integration/test_mode3_flow.py::test_mode3_extended_flow PASSED
============================== 6 passed in XX.XXs ==============================
```

### Security Tests in Detail

`test_mode3_invalid_token_rejected` proves the backend enforces Keycloak authentication before any agent call is made:

```python
response = requests.post(
    f"{backend_url}/optimization/start",
    headers={"Authorization": "Bearer invalid-token"},
    json={"prompt": "test"},
)
assert response.status_code in [401, 403]
```

`test_mode3_no_auth_header_rejected` confirms unauthenticated requests are rejected at the backend boundary — the AAuth flow never even starts:

```python
response = requests.post(
    f"{backend_url}/optimization/start",
    json={"prompt": "test"},   # no Authorization header
)
assert response.status_code in [401, 403]
```

These two tests together prove the layered security model: OIDC at the backend boundary, AAuth at the agent-to-agent boundary.

### What Agentgateway Logs in Mode 3

When a request passes with a valid auth-token, agentgateway logs the AAuth metadata:

```bash
info request aauth.scheme=Jwt aauth.agent=http://backend.localhost:8000
     token_audience=http://supply-chain-agent.localhost:3000 authenticated=false
     http.method=POST http.status=200 duration=145ms
```

When the CEL policy blocks an unauthorized agent, you see:

```bash
info request aauth.scheme=Jwks aauth.agent=http://unknown-agent.localhost
     http.status=403 authorization_denied=true
```

[Next: Agent Authorization with User Consent →](./agent-authorization-on-behalf-of.md)

[← Back to index](index.md)
