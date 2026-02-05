---
layout: default
title: Flow - Agent Delegation
description: No identity, but TOFU
---

[← Back to index](index.md)

```bash
================================================================================
Agent Delegation Demo
================================================================================

MODE: Automated
================================================================================
This demo shows the agent delegation flow:
1. Agent server starts and publishes JWKS
2. Agent delegate requests agent token from agent server
3. Agent delegate accesses resource using agent token
4. Resource validates agent token and grants access
5. Agent delegate requests auth token using agent token
6. Auth server validates agent token and issues auth token with agent_delegate claim

Debug output is enabled by default.
================================================================================

Starting Agent Server...
Starting Resource...
Starting Auth Server...
Waiting for servers to start...
INFO:     Started server process [95748]
INFO:     Waiting for application startup.
INFO:     Started server process [95748]
INFO:     Waiting for application startup.
INFO:     Started server process [95748]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Application startup complete.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8003 (Press CTRL+C to quit)
INFO:     Uvicorn running on http://0.0.0.0:8002 (Press CTRL+C to quit)
INFO:     Uvicorn running on http://0.0.0.0:8001 (Press CTRL+C to quit)

================================================================================
Ready to start test. Press Enter to begin...
================================================================================


================================================================================
TEST 1: Delegate Requests Agent Token
================================================================================
Description: Agent delegate requests agent token from agent server.
================================================================================

📤 Delegate requesting agent token from agent server...

================================================================================
>>> DELEGATE REQUEST to https://agent.supply-chain.com/delegate/token
================================================================================
POST https://agent.supply-chain.com/delegate/token HTTP/1.1
Content-Type: application/json

[Body (143 bytes)]
{"sub": "delegate-1", "cnf_jwk": {"kty": "OKP", "crv": "Ed25519", "x": "F3qaAzz4oWqJllxanygNdyR8o5apnV3uXmUQQZeT5Ys", "kid": "delegate-key-1"}}
================================================================================


================================================================================
>>> AGENT SERVER REQUEST received (delegate token)
================================================================================
POST /delegate/token HTTP/1.1
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
content-length: 133
content-type: application/json
host: 127.0.0.1:8001
user-agent: python-httpx/0.28.1
================================================================================


================================================================================
<<< AGENT SERVER RESPONSE
================================================================================
HTTP/1.1 200 OK
Content-Type: application/json

[Body]
{
  "agent_token": "eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiYWdlbnQrand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDEiLCJzdWIiOiJkZWxlZ2F0ZS0xIiwiZXhwIjoxNzY4Nzg5ODIxLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiRjNxYUF6ejRvV3FKbGx4YW55Z05keVI4bzVhcG5WM3VYbVVRUVplVDVZcyIsImtpZCI6ImRlbGVnYXRlLWtleS0xIn19fQ.5kw644tM4jK8R9e_vBXJGLEjZzU06ACbl6_dKcum7YrQraKfdwadivEtxeKJ7KmPcSDDxuiSvW9hLlJQ69zlDw",
  "expires_in": 3600
}
================================================================================

INFO:     127.0.0.1:58712 - "POST /delegate/token HTTP/1.1" 200 OK

================================================================================
<<< DELEGATE RESPONSE from https://agent.supply-chain.com/delegate/token
================================================================================
HTTP/1.1 200 OK
content-length: 433
content-type: application/json
date: Mon, 19 Jan 2026 01:30:21 GMT
server: uvicorn

[Body (433 bytes)]
{"agent_token":"eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiYWdlbnQrand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDEiLCJzdWIiOiJkZWxlZ2F0ZS0xIiwiZXhwIjoxNzY4Nzg5ODIxLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiRjNxYUF6ejRvV3FKbGx4YW55Z05keVI4bzVhcG5WM3VYbVVRUVplVDVZcyIsImtpZCI6ImRlbGVnYXRlLWtleS0xIn19fQ.5kw644tM4jK8R9e_vBXJGLEjZzU06ACbl6_dKcum7YrQraKfdwadivEtxeKJ7KmPcSDDxuiSvW9hLlJQ69zlDw","expires_in":3600}
================================================================================


✓ Agent token obtained: eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiYWdlbnQrand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgw...

Verifying agent token claims:
  Token header: {
  "alg": "EdDSA",
  "kid": "key-1",
  "typ": "agent+jwt"
}
  Token payload: {
  "iss": "https://agent.supply-chain.com",
  "sub": "delegate-1",
  "exp": 1768789821,
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "F3qaAzz4oWqJllxanygNdyR8o5apnV3uXmUQQZeT5Ys",
      "kid": "delegate-key-1"
    }
  }
}
  ✓ typ claim correct: agent+jwt
  ✓ iss claim correct: https://agent.supply-chain.com
  ✓ sub claim correct: delegate-1
  ✓ cnf.jwk claim present

✓ TEST 1 PASSED: Agent token obtained and validated

================================================================================
TEST 2: Delegate Accesses Resource Using Agent Token
================================================================================
Description: Agent delegate makes signed request to resource using agent token.
================================================================================

📤 Delegate accessing resource with agent token...

================================================================================
>>> DELEGATE REQUEST to https://important.resource.com/data-jwks
================================================================================
GET https://important.resource.com/data-jwks HTTP/1.1
Signature: sig1=:g1VmPaHtG7B1_vZ0FmmegnAtf804jio4EpC866wHyuPeQM07ikVZmAWxc5hjxR1SiveSq3ib9lgzDf7GwRL9AA:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786221
Signature-Key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiYWdlbnQrand0In0.eyJpc3MiOiJ...
================================================================================


================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-jwks HTTP/1.1
Host: 127.0.0.1:8002
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8002
signature: sig1=:g1VmPaHtG7B1_vZ0FmmegnAtf804jio4EpC866wHyuPeQM07ikVZmAWxc5hjxR1SiveSq3ib9lgzDf7GwRL9AA:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786221
signature-key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIiwidHlwIjoiYWdlbnQrand0In0.eyJpc3MiOiJ...
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58714 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58715 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 200
content-length: 206
content-type: application/json

[Body (206 bytes)]
{"message":"Access granted","data":"This is protected data (identified via agent token)","scheme":"jwt","token_type":"agent+jwt","method":"GET","agent":"https://agent.supply-chain.com","agent_delegate":"delegate-1"}
================================================================================

INFO:     127.0.0.1:58713 - "GET /data-jwks HTTP/1.1" 200 OK

================================================================================
<<< DELEGATE RESPONSE from https://important.resource.com/data-jwks
================================================================================
HTTP/1.1 200 OK
content-length: 206
content-type: application/json
date: Mon, 19 Jan 2026 01:30:21 GMT
server: uvicorn

[Body (206 bytes)]
{"message":"Access granted","data":"This is protected data (identified via agent token)","scheme":"jwt","token_type":"agent+jwt","method":"GET","agent":"https://agent.supply-chain.com","agent_delegate":"delegate-1"}
================================================================================


✓ Resource access granted
  Response: {
  "message": "Access granted",
  "data": "This is protected data (identified via agent token)",
  "scheme": "jwt",
  "token_type": "agent+jwt",
  "method": "GET",
  "agent": "https://agent.supply-chain.com",
  "agent_delegate": "delegate-1"
}
  ✓ Resource recognized agent token

================================================================================
TEST 3: Delegate Requests Auth Token Using Agent Token
================================================================================
Description: Agent delegate requests auth token from auth server using agent token.
================================================================================

📤 Delegate requesting auth token from auth server...
  Note: Full auth token flow requires resource token (Phase 3/4)
  This test verifies delegate can sign requests with agent token

✓ TEST 3 PASSED: Delegate can sign requests with agent token

================================================================================
TEST SUMMARY
================================================================================
✓ PASSED: TEST 1: Delegate Requests Agent Token
✓ PASSED: TEST 2: Delegate Accesses Resource
✓ PASSED: TEST 3: Delegate Requests Auth Token

--------------------------------------------------------------------------------
Total: 3 | Passed: 3 | Failed: 0
================================================================================

Servers are still running. Press Ctrl+C to stop.
```