# AAuth Integration Guide

This guide provides step-by-step instructions for testing the integration between the Agent Gateway (`agentgateway`) and the AAuth external authorization service (`extauth-aauth-resource`). This setup provides native AAuth (Agent Authorization) protocol protection for your agent backends.

## 1. Architecture Overview

- **Gateway (`agentgateway`)**: Intercepts HTTP traffic on port `3000`. Using the `extAuthz` policy, it pauses incoming requests, forwards the HTTP headers and metadata to the AAuth service via gRPC on `localhost:7070`, and enforces the resulting allow/deny decision.
- **AAuth Service (`extauth-aauth-resource`)**: Runs in the background listening on `localhost:7070` for `ext_authz` gRPC calls. It validates HTTP Message Signatures (RFC 9421) and mints AAuth tokens. It also runs an HTTP server on `localhost:8081` serving standard AAuth endpoints like the JWKS URL (`/.well-known/aauth-resource.json`).

## 2. Directory & Configuration Setup

All relevant configurations live inside the `agentgateway/` folder. Ensure you are working from there.

1. **`agentgateway/config.yaml`**: The gateway configuration. To allow external agents to discover the AAuth configuration seamlessly, the gateway is configured to proxy `/.well-known/` and `/resource/` requests directly to the AAuth HTTP server (`localhost:8081`). The catch-all route enforces the `extAuthz` policy (pointing to `localhost:7070`).
2. **`agentgateway/aauth-config.yaml`**: The policy engine configuration. Notice the `hosts` mappings, which the AAuth service uses to match requests to specific resource IDs (`supply-chain-api` and `market-analysis-api`).
3. **`agentgateway/resource_key.pem`**: The EdDSA Ed25519 private key the AAuth service uses to sign tokens.

---

## 3. Running the Services

You must run both services concurrently. Open two terminal windows.

### Terminal 1: Start the AAuth Service

Run this daemon from the `agentgateway` directory so it can find its key material:

```bash
cd agentgateway/
AAUTH_CONFIG=aauth-config.yaml ~/go/src/github.com/christian-posta/extauth-aauth-resource/aauth-service
```
*You should see logs indicating it has started on ports `8081` (HTTP) and `7070` (gRPC).*

### Terminal 2: Start the Agent Gateway

Run the gateway from the same directory:

```bash
cd agentgateway/
./agw -f config.yaml
```
*You should see logs indicating the server is ready and bound to `bind/3000`.*

---

## 4. Testing End-to-End Manually

Open a third terminal window for sending requests.

### Test A: Unauthenticated Request (Failure)

When you make a standard request without AAuth signature headers, the proxy forwards it to the AAuth service, which generates a challenge.

```bash
curl -i -X POST 'http://localhost:3000/' \
  -H 'Host: supply-chain-agent.localhost' \
  -H 'Content-Type: application/json' \
  -d '{}'
```

**Expected Result:**
You will receive a `401 Unauthorized` containing an `AAuth-Requirement` header.
```http
HTTP/1.1 401 Unauthorized
aauth-requirement: requirement=auth-token, auth-server=""
www-authenticate: AAuth
content-type: application/json

{"error":"missing_signature"}
```
*(Check Terminal 1: You should see the AAuth service log `missing_signature` for `supply-chain-api`.)*

### Test B: Valid Signed Request (Success)

Because AAuth requires highly specific HTTP Message Signatures (RFC 9421) and timestamps, manually constructing `curl` commands by hand is almost impossible.

To generate a valid request dynamically, use the helper script provided by the `extauth-aauth-resource` repository. 

Run this command, which compiles the helper, generates a fresh signature valid for the current timestamp, and pipes it directly to your terminal to execute via `curl`:

```bash
cd ~/go/src/github.com/christian-posta/extauth-aauth-resource
go run ./cmd/sign-request \
  -method POST \
  -authority "supply-chain-agent.localhost" \
  -path "/" \
  -body "{}" \
  | sed 's|http://supply-chain-agent.localhost/|http://localhost:3000/|g' \
  | sed "s/-H 'Content-Type:/-H 'Host: supply-chain-agent.localhost' -H 'Content-Type:/g" \
  | bash
```

**Expected Result:**
The AAuth service successfully validates the signature and allows the request through. The gateway then forwards the request to the upstream target (`localhost:9999`). 

Because there is currently no backend running on port `9999`, you will see this response:

```http
HTTP/1.1 503 Service Unavailable
content-type: text/plain

upstream call failed: Connect: Connection refused (os error 61)
```

**This is a success condition!** It proves the request passed authorization and the gateway attempted to route it to the backend. 
*(Check Terminal 1: You should see the AAuth service log `result: allowed` with the `pseudonymous` identity level.)*

### Test C: Verify the JWKS Endpoint via the Gateway

The gateway is configured to proxy AAuth metadata paths to the AAuth service. In the current local setup, the live gateway on port `3000` returns `Not Found` for these JWKS requests, while the AAuth service on port `8081` returns the expected host-specific JWKS documents.

Query the gateway's public port (`3000`):

```bash
curl -s "http://localhost:3000/.well-known/jwks.json" -H "Host: supply-chain-agent.localhost"
```

**Observed Result via Agent Gateway (`3000`):**

```text
Not Found
```

To verify the actual resource JWKS being served for each host, query the AAuth service directly on port `8081`:

```bash
curl -s "http://localhost:8081/.well-known/jwks.json" -H "Host: supply-chain-agent.localhost"
curl -s "http://localhost:8081/.well-known/jwks.json" -H "Host: market-analysis-agent.localhost"
```

**Observed Result for `supply-chain-agent.localhost` via AAuth service (`8081`):**

```json
{
  "keys": [
    {
      "alg": "EdDSA",
      "crv": "Ed25519",
      "kid": "spa-rsk-1",
      "kty": "OKP",
      "use": "sig",
      "x": "A1OC-KnIa9wVRFJmnjrTfPJfl8gYDOjSCV_KJFmxHSg"
    }
  ]
}
```

**Observed Result for `market-analysis-agent.localhost` via AAuth service (`8081`):**

```json
{
  "keys": [
    {
      "alg": "EdDSA",
      "crv": "Ed25519",
      "kid": "maa-rsk-1",
      "kty": "OKP",
      "use": "sig",
      "x": "rMep_GRARP4z5aSb16ORzDnoeHU_6rMeJb1Z3Pdn0CI"
    }
  ]
}
```
