---
layout: default
title: Agent Authorization (Autonomous)
---

# Agent Authorization (Autonomous)

In this demo, we'll use Agent Identity Authorization provided by Keycloak [as described in details in this flow](./flow-03-authz.md). For the draft of [AAuth please visit the GitHub repo](https://github.com/dickhardt/agent-auth). 

[← Back to index](index.md)

## Run the components

To run this demo, [please set up the prerequisites](./install-aauth-keycloak.md) (Keycloak, Agentgateway, Jaeger). 


### Restart Some Components

We will restart the `supply-chain-agent` and `market-analysis-agent` with new parameters to trigger the authorization challenge and flow. 

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
      > uv run . --signature-scheme jwks --authorization-scheme autonomous
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

At this point you're ready to return to the UI to review the demo flow:

## Walking through the Demo Flow

From the main UI page, if you click the `"Optimize Laptop Supply Chain"` button, it should kick off the flow for the backend components. You may need to refresh the page (some time the OIDC token / User session expires). 

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

When backend makes a call to supply-chain-agent, it will see a 401 and an "agent-auth" header. This header will have the resource token which binds the needed scopes (as determined by the resource) to the agent who's calling (backend in this case). Let's take a look at what the `backend` logs look like:

```bash
INFO:aauth.tokens:🔐 401 from supply-chain-agent (url=http://supply-chain-agent.localhost:3000): headers={'date': 'Fri, 06 Feb 2026 22:12:49 GMT', 'server': 'uvicorn', 'agent-auth': 'httpsig; auth-token; resource_token="eyJhbGciOiJFZERTQSIsImtpZCI6InN1cHBseS1jaGFpbi1hZ2VudC1lcGhlbWVyYWwtMSIsInR5cCI6InJlc291cmNlK2p3dCJ9.eyJpc3MiOiJodHRwOi8vc3VwcGx5LWNoYWluLWFnZW50LmxvY2FsaG9zdDozMDAwIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9hYXV0aC10ZXN0IiwiYWdlbnQiOiJodHRwOi8vYmFja2VuZC5sb2NhbGhvc3Q6ODAwMCIsImFnZW50X2prdCI6Il9YUHA3YmZNdDV1Z25yUnFBU1VuS2JaRW5rd2JrRmpwb01GQS1lemVYS3ciLCJleHAiOjE3NzA0MTYyNzAsInNjb3BlIjoic3VwcGx5LWNoYWluOm9wdGltaXplIn0.ZAUQNnQz76zSbp4XGRyST_K5b0wVavVys5sYIUKJwLWe6LnJqN6By-37jdXDuup5c9nGak3iXw1MlaqAIdkgDQ"; auth_server="http://localhost:8080/realms/aauth-test"', 'content-length': '22', 'content-type': 'text/plain; charset=utf-8'}
INFO:     127.0.0.1:55612 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:55612 - "GET /jwks.json HTTP/1.1" 200 OK
```
{: .log-output}

Here we can see that we got a `401` when `backend` tried to call `supply-chain-agent` and it also returned an `agent-auth` header with requirements to upgrade to `httpsig; auth-token` with a resource token. This resource token binds a request for scopes to call this `supply-chain-agent` to the `backend` caller. If we decode the JWT resource token it looks like this:

```json
{
  "iss": "http://supply-chain-agent.localhost:3000",
  "aud": "http://localhost:8080/realms/aauth-test",
  "agent": "http://backend.localhost:8000",
  "agent_jkt": "_XPp7bfMt5ugnrRqASUnKbZEnkwbkFjpoMFA-ezeXKw",
  "exp": 1770416270,
  "scope": "supply-chain:optimize"
}
```

Please see the [Authorization flow](./flow-03-authz.md) to understand these claims in more detail. To keep it short, this token proves that `backend` was trying to call `supply-chain-agent` and the scopes necessary to make this call. The `aud` for this is the Authorization Server (Keycloak in our demo) that the Agent trusts. 


If we look at the logs for the `supply-chain-agent`, we can see JWKS was used to verify the agent's identity:

```bash
INFO:http_headers_middleware:🔐 AAuth headers received: ['signature', 'signature-key', 'signature-input']
INFO:agent_executor:🔐 AAuth signature headers detected: ['signature', 'signature-key', 'signature-input']
INFO:agent_executor:🔐 AAuth scheme: JWKS - identified agent
INFO:agent_executor:🔐 Verifying AAuth signature (scheme: jwks)
INFO:agent_executor:🔐 VERIFYING with: method=POST, target_uri='http://supply-chain-agent.localhost:3000/'
INFO:aauth.signing:🔐 VERIFIER: verify_signature() called
INFO:aauth.signing:🔐 VERIFIER: method=POST, target_uri=http://supply-chain-agent.localhost:3000/
INFO:aauth.signing:🔐 VERIFIER: signature_input_header=sig1=("@method" "@authority" "@path" "signature-key");created=1770415970
INFO:httpx:HTTP Request: GET http://backend.localhost:8000/.well-known/aauth-agent "HTTP/1.1 200 OK"
INFO:httpx:HTTP Request: GET http://backend.localhost:8000/jwks.json "HTTP/1.1 200 OK"
INFO:agent_executor:✅ AAuth signature verification successful
INFO:agent_executor:🔐 Authorization required: auth_token missing or invalid
```
{: .log-output}

You can see the identity of the caller has been established, but this call requires `auth_token`. Further down in the logs, you can see the `supply-chain-agent` creates a Resource token and responds with `HTTP 401`:


```bash
INFO:resource_token_service:✅ Resource token generated successfully
INFO:aauth.tokens:🔐 Issuing resource_token: eyJhbGciOiJFZERTQSIsImtpZCI6InN1cHBseS1jaGFpbi1hZ2VudC1lcGhlbWVyYWwtMSIsInR5cCI6InJlc291cmNlK2p3dCJ9.eyJpc3MiOiJodHRwOi8vc3VwcGx5LWNoYWluLWFnZW50LmxvY2FsaG9zdDozMDAwIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9hYXV0aC10ZXN0IiwiYWdlbnQiOiJodHRwOi8vYmFja2VuZC5sb2NhbGhvc3Q6ODAwMCIsImFnZW50X2prdCI6Il9YUHA3YmZNdDV1Z25yUnFBU1VuS2JaRW5rd2JrRmpwb01GQS1lemVYS3ciLCJleHAiOjE3NzA0MTYyNzAsInNjb3BlIjoic3VwcGx5LWNoYWluOm9wdGltaXplIn0.ZAUQNnQz76zSbp4XGRyST_K5b0wVavVys5sYIUKJwLWe6LnJqN6By-37jdXDuup5c9nGak3iXw1MlaqAIdkgDQ
INFO:agent_executor:🔐 Issuing resource_token for agent: http://backend.localhost:8000
INFO:agent_executor:🔐 Returning 401 with Agent-Auth header
```
{: .log-output}

When the `backend` has the resource token, it can go to the auth server and request an auth token. With Keycloak running, we can see the following log from `backend`:

```bash
INFO:aauth.tokens:🔐 Received auth_token from auth server: eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiYXV0aCtqd3QiLCJraWQiIDogIjF2SGZlTWk5U0E4VTdWZlNKRTN3SnVTQklOZUhVeWpOY0pzZ2tYWWNHQlkifQ.eyJleHAiOjE3NzA0MTYyNzAsImlhdCI6MTc3MDQxNTk3MCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9hYXV0aC10ZXN0IiwiYXVkIjoiaHR0cDovL3N1cHBseS1jaGFpbi1hZ2VudC5sb2NhbGhvc3Q6MzAwMCIsImFnZW50IjoiaHR0cDovL2JhY2tlbmQubG9jYWxob3N0OjgwMDAiLCJjbmYiOnsiandrIjp7ImtpZCI6IjFpUHZER1dzcHJYcWpSY2ZlSGtsRThWVmpEY0xKWndkZTEycW1xemN2RjAiLCJrdHkiOiJPS1AiLCJ1c2UiOiJzaWciLCJjcnYiOiJFZDI1NTE5IiwieCI6IjE3YjFaWjFhVlJSZ1VjcVA0UE94TG5mMThoa0lqU2N5T1p5NXVQX3MzUTAifX0sInNjb3BlIjoic3VwcGx5LWNoYWluOm9wdGltaXplIn0.QAcEFcaW46-TNCVEn5u5uFC-_9nXP7bFE__EkbG7gvKO66xWePUfOJALRJ7G68JX45iZNRrtm4gNTH9axWNWkoWBPTkauR8fMdX-3Hh6BcM0lKC7vBH6iLIws7hWM0d3Cmwwd3QdIkiOhydbeka3IZ0MzUi5p-PUiZp7siGLONfG2D7mbhaf00t3QNrabdaNwMd3kUniqpm3nUhb-j7d2vruxuX6cPHvIdWS6B3x3dprCH71wb97-js6IVgBsew2XLh15_BeAykA4iM_jp4YF3Rpy9hDB3SzFRN8S6frenLkAh3TRnk4Ii5fXMJEyGwuduQmP7oxn_xW4kzJvdLYVw
INFO:     127.0.0.1:55603 - "POST /optimization/start HTTP/1.1" 200 OK
INFO:     127.0.0.1:55603 - "OPTIONS /optimization/progress/5cb9b75d-b160-4142-8042-0ffa47b7a2de HTTP/1.1" 200 OK
INFO:     127.0.0.1:55603 - "GET /optimization/progress/5cb9b75d-b160-4142-8042-0ffa47b7a2de HTTP/1.1" 200 OK
```
{: .log-output}

Keycloak has issued us an AAuth token! Let's decode that token:

```json
{
  "exp": 1770416270,
  "iat": 1770415970,
  "iss": "http://localhost:8080/realms/aauth-test",
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

The key parts of this token:

* **aud** this token is for the `supply-chain-agent`
* **agent** this token is issued to the verified identity of the call (and which matched the `agent` from the resource token)
* **cnf** this token is issued to the `backend` and only the backend can use it. This `cnf.jwk` is pinned to the `backend`'s keys. 

Now, when the `backend` calls the `supply-chain-agent` it will use the `jwt` scheme. That is, the authorization token that has been pinned to the backend's keys. So the backend will sign the message with its keys and present the JWT to verify it's identity. Please see the [Authorization flow](./flow-03-authz.md) for more. 

Now when `supply-chain-agent` gets this request, with the right scheme and authorization token, it will allow the call to proceed successfully and return a result:

```bash

INFO:agent_executor:✅ AAuth signature verification successful
INFO:aauth.tokens:🔐 Received auth_token in request (HTTPSig scheme=jwt): eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiYXV0aCtqd3QiLCJraWQiIDogIjF2SGZlTWk5U0E4VTdWZlNKRTN3SnVTQklOZUhVeWpOY0pzZ2tYWWNHQlkifQ.eyJleHAiOjE3NzA0MTYyNzAsImlhdCI6MTc3MDQxNTk3MCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9hYXV0aC10ZXN0IiwiYXVkIjoiaHR0cDovL3N1cHBseS1jaGFpbi1hZ2VudC5sb2NhbGhvc3Q6MzAwMCIsImFnZW50IjoiaHR0cDovL2JhY2tlbmQubG9jYWxob3N0OjgwMDAiLCJjbmYiOnsiandrIjp7ImtpZCI6IjFpUHZER1dzcHJYcWpSY2ZlSGtsRThWVmpEY0xKWndkZTEycW1xemN2RjAiLCJrdHkiOiJPS1AiLCJ1c2UiOiJzaWciLCJjcnYiOiJFZDI1NTE5IiwieCI6IjE3YjFaWjFhVlJSZ1VjcVA0UE94TG5mMThoa0lqU2N5T1p5NXVQX3MzUTAifX0sInNjb3BlIjoic3VwcGx5LWNoYWluOm9wdGltaXplIn0.QAcEFcaW46-TNCVEn5u5uFC-_9nXP7bFE__EkbG7gvKO66xWePUfOJALRJ7G68JX45iZNRrtm4gNTH9axWNWkoWBPTkauR8fMdX-3Hh6BcM0lKC7vBH6iLIws7hWM0d3Cmwwd3QdIkiOhydbeka3IZ0MzUi5p-PUiZp7siGLONfG2D7mbhaf00t3QNrabdaNwMd3kUniqpm3nUhb-j7d2vruxuX6cPHvIdWS6B3x3dprCH71wb97-js6IVgBsew2XLh15_BeAykA4iM_jp4YF3Rpy9hDB3SzFRN8S6frenLkAh3TRnk4Ii5fXMJEyGwuduQmP7oxn_xW4kzJvdLYVw
INFO:agent_executor:🔐 Auth token detected in request (scheme=jwt)
INFO:httpx:HTTP Request: GET http://localhost:8080/realms/aauth-test/protocol/openid-connect/certs "HTTP/1.1 200 OK"
INFO:agent_executor:✅ Auth token verified successfully
INFO:agent_executor:✅ Authorization successful: auth_token verified for agent: http://backend.localhost:8000
INFO:agent_executor:🔐 Extracted upstream auth_token for token exchange (length: 945)
INFO:agent_executor:🔐 Using AAuth JWKS signing for downstream agent calls
INFO:agent_executor:🔐 Upstream auth_token available for token exchange if needed
INFO:     127.0.0.1:55606 - "POST / HTTP/1.1" 200 OK
```
{: .log-output}


## Tracing from Jaeger:

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
    BE -->|3. Exchange for auth_token| KC[Keycloak]
    KC -->|4. auth_token| BE
    BE -->|5. Retry with auth_token| AGW --> SCA
```

**Key:** Supply-Chain Agent challenges with resource_token → Backend exchanges it at Keycloak for auth_token → Retry succeeds with JWT authorization.

[In the next post](./agent-authorization-on-behalf-of.md), we'll look at how [AAuth authorization works when it requires User consent](./flow-04-authz.md) in this demo! Specifically, how do we tie the OIDC login to a user-consent needed by the AAuth protocol? [Head to the next section](./agent-authorization-on-behalf-of.md)

[← Back to index](index.md)
