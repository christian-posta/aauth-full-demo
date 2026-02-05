---
layout: default
title: Flow - Token Exchange
description: No identity, but TOFU
---

[← Back to index](index.md)

```bash
================================================================================
Token Exchange Demo
================================================================================

MODE: Automated
================================================================================
This demo shows the token exchange flow:
1. Agent 1 obtains auth_token for Resource 1 from Auth Server 1
2. Agent 1 accesses Resource 1 with auth_token
3. Resource 1 needs to call Resource 2 to fulfill the request
4. Resource 1 receives 401 challenge from Resource 2 with resource_token
5. Resource 1 exchanges upstream auth_token for downstream auth_token at Auth Server 2
6. Auth Server 2 validates upstream token, trusts Auth Server 1, issues token with 'act' claim
7. Resource 1 accesses Resource 2 with exchanged token
8. Resource 1 returns aggregated response to Agent 1

Debug output is enabled by default.
================================================================================

Starting Agent 1...
Starting Resource 1...
Starting Resource 2...
Starting Auth Server 1...
Starting Auth Server 2...
Waiting for servers to start...
INFO:     Started server process [95877]
INFO:     Waiting for application startup.
INFO:     Started server process [95877]
INFO:     Waiting for application startup.
INFO:     Started server process [95877]
INFO:     Waiting for application startup.
INFO:     Started server process [95877]
INFO:     Waiting for application startup.
INFO:     Started server process [95877]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Application startup complete.
INFO:     Application startup complete.
INFO:     Application startup complete.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8001 (Press CTRL+C to quit)
INFO:     Uvicorn running on http://0.0.0.0:8003 (Press CTRL+C to quit)
INFO:     Uvicorn running on http://0.0.0.0:8002 (Press CTRL+C to quit)
INFO:     Uvicorn running on http://0.0.0.0:8005 (Press CTRL+C to quit)
INFO:     Uvicorn running on http://0.0.0.0:8004 (Press CTRL+C to quit)

================================================================================
Starting tests...
================================================================================

================================================================================
TEST 1: Agent 1 Obtains Auth Token for Resource 1
================================================================================
Description: Agent 1 requests auth token from Auth Server 1 for Resource 1.
================================================================================

📤 Agent 1 requesting auth token for Resource 1...

================================================================================
>>> AGENT REQUEST to http://127.0.0.1:8002/data-auth
================================================================================
GET http://127.0.0.1:8002/data-auth HTTP/1.1
Signature: sig1=:bfJBXxQfM_-qjKpgUnjsHF_vjkGkMfSvZvcjCR7n0QXGuOWosMpgdQmDraokNjr41wkdy75dfIS-7FXkrjeaDw:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786273
Signature-Key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")
================================================================================


================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-auth HTTP/1.1
Host: 127.0.0.1:8002
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8002
signature: sig1=:bfJBXxQfM_-qjKpgUnjsHF_vjkGkMfSvZvcjCR7n0QXGuOWosMpgdQmDraokNjr41wkdy75dfIS-7FXkrjeaDw:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786273
signature-key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58718 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58719 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 401
agent-auth: httpsig; auth-token; resource_token="eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoi...
content-length: 22

[Body (22 bytes)]
Authorization required
================================================================================

INFO:     127.0.0.1:58717 - "GET /data-auth HTTP/1.1" 401 Unauthorized

================================================================================
<<< AGENT RESPONSE from http://127.0.0.1:8002/data-auth
================================================================================
HTTP/1.1 401 Unauthorized
agent-auth: httpsig; auth-token; resource_token="eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoi...
content-length: 22
date: Mon, 19 Jan 2026 01:31:13 GMT
server: uvicorn

[Body (22 bytes)]
Authorization required
================================================================================

INFO:     127.0.0.1:58720 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK

================================================================================
>>> AGENT REQUEST to http://127.0.0.1:8003/agent/token
================================================================================
POST http://127.0.0.1:8003/agent/token HTTP/1.1
Content-Digest: sha-256=:Fcjm6yHvR96HB/jUtepWiP8WWE4IjEmjyoecGPccDOw=:
Content-Type: application/x-www-form-urlencoded
Signature: sig1=:-cxGlWSvyaoSrHQ0XbhsTC3VRowsek8XdsO00POA5LanW3U7Ra6A6AYaV06OQLA9uo1JOZ7cz19nYq79q2fsAA:
Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
Signature-Key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")

[Body (510 bytes)]
request_type=auth&resource_token=eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoicmVzb3VyY2Urand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDIiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDMiLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSIsImFnZW50X2prdCI6IjRPSFhOMHZBVnJtSEoyeDloMWVYejZlVl9sLUVvc0hWQ2dnaEdiR25CREUiLCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg2ODczfQ.Eibyqh1nM1SQkXyggP2W2FuoJO4l0iGufNekJ4oUb22UWLi1Eah0QHwFCdbJ1AXLH9y_lYTec7Hvwu7aC9jdAA&redirect_uri=http://127.0.0.1:8001/callback
================================================================================


================================================================================
>>> AUTH SERVER REQUEST received
================================================================================
POST /agent/token HTTP/1.1
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
content-digest: sha-256=:Fcjm6yHvR96HB/jUtepWiP8WWE4IjEmjyoecGPccDOw=:
content-length: 510
content-type: application/x-www-form-urlencoded
host: 127.0.0.1:8003
signature: sig1=:-cxGlWSvyaoSrHQ0XbhsTC3VRowsek8XdsO00POA5LanW3U7Ra6A6AYaV06OQLA9uo1JOZ7cz19nYq79q2fsAA:
signature-input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
signature-key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")
user-agent: python-httpx/0.28.1

[Body (510 bytes)]
request_type=auth&resource_token=eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoicmVzb3VyY2Urand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDIiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDMiLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSIsImFnZW50X2prdCI6IjRPSFhOMHZBVnJtSEoyeDloMWVYejZlVl9sLUVvc0hWQ2dnaEdiR25CREUiLCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg2ODczfQ.Eibyqh1nM1SQkXyggP2W2FuoJO4l0iGufNekJ4oUb22UWLi1Eah0QHwFCdbJ1AXLH9y_lYTec7Hvwu7aC9jdAA&redirect_uri=http://127.0.0.1:8001/callback
================================================================================

INFO:     127.0.0.1:58722 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58723 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58724 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58725 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58726 - "GET /.well-known/aauth-resource HTTP/1.1" 200 OK
INFO:     127.0.0.1:58727 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< AUTH SERVER RESPONSE
================================================================================
HTTP/1.1 200 OK
Content-Type: application/json

[Body]
{
  "auth_token": "eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDMiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDIiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiUkMtRXZmcnhyZjZ5T29qQ01Hall4d3NEcEZiNExLYTlFNFpMTnNHM3J3QSIsImtpZCI6ImtleS0xIn19LCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg5ODczLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSJ9.Wl1scb1W2MLmTS-oLkiDDBD5qNnr9x8cxqfwJSJ6KC1RV_850dlSmTHUpQ7TNAy8N3XgSQITNee_Gh9YzacFCA",
  "expires_in": 3600,
  "token_type": "Bearer"
}
================================================================================

INFO:     127.0.0.1:58721 - "POST /agent/token HTTP/1.1" 200 OK

================================================================================
<<< AGENT RESPONSE from http://127.0.0.1:8003/agent/token
================================================================================
HTTP/1.1 200 OK
content-length: 545
content-type: application/json
date: Mon, 19 Jan 2026 01:31:13 GMT
server: uvicorn

[Body (545 bytes)]
{"auth_token":"eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDMiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDIiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiUkMtRXZmcnhyZjZ5T29qQ01Hall4d3NEcEZiNExLYTlFNFpMTnNHM3J3QSIsImtpZCI6ImtleS0xIn19LCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg5ODczLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSJ9.Wl1scb1W2MLmTS-oLkiDDBD5qNnr9x8cxqfwJSJ6KC1RV_850dlSmTHUpQ7TNAy8N3XgSQITNee_Gh9YzacFCA","expires_in":3600,"token_type":"Bearer"}
================================================================================


================================================================================
>>> AGENT REQUEST to http://127.0.0.1:8002/data-auth
================================================================================
GET http://127.0.0.1:8002/data-auth HTTP/1.1
Signature: sig1=:r4bCepCmQ5T0rS8nnzZisfKYe6QGJvOvvDx5js9mBh4qBA3KcSx8ysWF6-uKQHvlmGQj05X_oB9XDCCNlz_VDQ:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786273
Signature-Key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...
================================================================================


================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-auth HTTP/1.1
Host: 127.0.0.1:8002
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8002
signature: sig1=:r4bCepCmQ5T0rS8nnzZisfKYe6QGJvOvvDx5js9mBh4qBA3KcSx8ysWF6-uKQHvlmGQj05X_oB9XDCCNlz_VDQ:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786273
signature-key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58729 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
INFO:     127.0.0.1:58730 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58731 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
INFO:     127.0.0.1:58732 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 200
content-length: 212
content-type: application/json

[Body (212 bytes)]
{"message":"Access granted","data":"This is protected data (authorized)","scheme":"jwt","token_type":"auth+jwt","method":"GET","agent":"http://127.0.0.1:8001","agent_delegate":null,"scope":"data.read data.write"}
================================================================================

INFO:     127.0.0.1:58728 - "GET /data-auth HTTP/1.1" 200 OK

================================================================================
<<< AGENT RESPONSE from http://127.0.0.1:8002/data-auth
================================================================================
HTTP/1.1 200 OK
content-length: 212
content-type: application/json
date: Mon, 19 Jan 2026 01:31:13 GMT
server: uvicorn

[Body (212 bytes)]
{"message":"Access granted","data":"This is protected data (authorized)","scheme":"jwt","token_type":"auth+jwt","method":"GET","agent":"http://127.0.0.1:8001","agent_delegate":null,"scope":"data.read data.write"}
================================================================================


================================================================================
RESOURCE TOKEN (decoded)
================================================================================
Header:
{
  "alg": "EdDSA",
  "kid": "resource-key-1",
  "typ": "resource+jwt"
}

Payload:
{
  "iss": "http://127.0.0.1:8002",
  "aud": "http://127.0.0.1:8003",
  "agent": "http://127.0.0.1:8001",
  "agent_jkt": "4OHXN0vAVrmHJ2x9h1eXz6eV_l-EosHVCgghGbGnBDE",
  "scope": "data.read data.write",
  "exp": 1768786873
}
================================================================================


================================================================================
AUTH TOKEN (decoded)
================================================================================
Header:
{
  "alg": "EdDSA",
  "kid": "auth-key-1",
  "typ": "auth+jwt"
}

Payload:
{
  "iss": "http://127.0.0.1:8003",
  "aud": "http://127.0.0.1:8002",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "RC-Evfrxrf6yOojCMGjYxwsDpFb4LKa9E4ZLNsG3rwA",
      "kid": "key-1"
    }
  },
  "scope": "data.read data.write",
  "exp": 1768789873,
  "agent": "http://127.0.0.1:8001"
}
================================================================================


✓ Auth token obtained: eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4...

Verifying auth token claims:
  iss: http://127.0.0.1:8003
  aud: http://127.0.0.1:8002
  agent: http://127.0.0.1:8001
  scope: data.read data.write

✓ TEST 1 PASSED: Auth token obtained for Resource 1

================================================================================
TEST 2: Resource 1 Calls Resource 2 via Token Exchange
================================================================================
Description: Resource 1 needs data from Resource 2. It exchanges the upstream token
             for a new token from Auth Server 2, which includes an 'act' claim.
================================================================================

📤 Resource 1 calling Resource 2 with token exchange...

================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-auth HTTP/1.1
Host: 127.0.0.1:8004
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8004
signature: sig1=:QyF8FyJHa_L2yYg7_wJL-VUv3oVIQcbQK8UDH3K8zaTTvFYoS3wVoy090jMt330QBvRKZ8Vl46_2iqs8Fn3eAA:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786273
signature-key: sig1=(scheme=jwks id="http://127.0.0.1:8002" kid="resource-key-1" well-known="aauth-resource")
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58734 - "GET /.well-known/aauth-resource HTTP/1.1" 200 OK
INFO:     127.0.0.1:58735 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 401
agent-auth: httpsig; auth-token; resource_token="eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoi...
content-length: 22

[Body (22 bytes)]
Authorization required
================================================================================

INFO:     127.0.0.1:58733 - "GET /data-auth HTTP/1.1" 401 Unauthorized

================================================================================
>>> TOKEN EXCHANGE REQUEST to http://127.0.0.1:8005/agent/token
================================================================================
POST http://127.0.0.1:8005/agent/token HTTP/1.1
Content-Digest: sha-256=:iPlDBazalrHGLswJx6HRsEUReW593fk1Fm9w8aoshDI=:
Content-Type: application/x-www-form-urlencoded
Signature: sig1=:ell-876hRnnrbm4EL1ZFDApnyrym2jT12mRJ4v76BSkBErc_Q_Ayz2dvTJATN4tgVby0nkhCy1g82rscdYcbBw:
Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
Signature-Key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...

[Body (470 bytes)]
request_type=exchange&resource_token=eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoicmVzb3VyY2Urand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDQiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDUiLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMiIsImFnZW50X2prdCI6Im5OMlh1bVF0RGxlRjBEY3VhTmNGX0Vuel85RWV6RVQ0R0syajRRV1BxUnciLCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg2ODczfQ.PUNdR--sr34sO-fR0iuGpF0kRQAbLm-6v9Xd_VgWU_z_4ertOILCalou__Aw7MyZM1LatQrD-hz_zxHuxKcZCA
================================================================================


================================================================================
>>> AUTH SERVER REQUEST received
================================================================================
POST /agent/token HTTP/1.1
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
content-digest: sha-256=:iPlDBazalrHGLswJx6HRsEUReW593fk1Fm9w8aoshDI=:
content-length: 470
content-type: application/x-www-form-urlencoded
host: 127.0.0.1:8005
signature: sig1=:ell-876hRnnrbm4EL1ZFDApnyrym2jT12mRJ4v76BSkBErc_Q_Ayz2dvTJATN4tgVby0nkhCy1g82rscdYcbBw:
signature-input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
signature-key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...
user-agent: python-httpx/0.28.1

[Body (470 bytes)]
request_type=exchange&resource_token=eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoicmVzb3VyY2Urand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDQiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDUiLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMiIsImFnZW50X2prdCI6Im5OMlh1bVF0RGxlRjBEY3VhTmNGX0Vuel85RWV6RVQ0R0syajRRV1BxUnciLCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg2ODczfQ.PUNdR--sr34sO-fR0iuGpF0kRQAbLm-6v9Xd_VgWU_z_4ertOILCalou__Aw7MyZM1LatQrD-hz_zxHuxKcZCA
================================================================================

INFO:     127.0.0.1:58737 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
INFO:     127.0.0.1:58738 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58739 - "GET /.well-known/aauth-resource HTTP/1.1" 200 OK
INFO:     127.0.0.1:58740 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58741 - "GET /.well-known/aauth-resource HTTP/1.1" 200 OK
INFO:     127.0.0.1:58742 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< AUTH SERVER RESPONSE (Token Exchange)
================================================================================
HTTP/1.1 200 OK
Content-Type: application/json

[Body]
{
  "auth_token": "eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDUiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDQiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiY0V1MUdwZmpDZ1hiejdvaTFlbXdPbFluZ0s0VERIQk9RbHJFRTdqVDdETSIsImtpZCI6InJlc291cmNlLWtleS0xIn19LCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg5ODczLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMiIsImFjdCI6eyJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSJ9fQ.iJRCDH4QSUJLfqLuEeuQEqF98NuWZ-49Q9LOhcnfRRmzqICFPPiWCPyIUpqrb704UFPeYlZ4VLt8bvX1GbHVDw",
  "expires_in": 3600
}
================================================================================

INFO:     127.0.0.1:58736 - "POST /agent/token HTTP/1.1" 200 OK

================================================================================
<<< TOKEN EXCHANGE RESPONSE from http://127.0.0.1:8005/agent/token
================================================================================
HTTP/1.1 200 OK
content-length: 589
content-type: application/json
date: Mon, 19 Jan 2026 01:31:13 GMT
server: uvicorn

[Body (589 bytes)]
{"auth_token":"eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDUiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDQiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiY0V1MUdwZmpDZ1hiejdvaTFlbXdPbFluZ0s0VERIQk9RbHJFRTdqVDdETSIsImtpZCI6InJlc291cmNlLWtleS0xIn19LCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg5ODczLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMiIsImFjdCI6eyJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSJ9fQ.iJRCDH4QSUJLfqLuEeuQEqF98NuWZ-49Q9LOhcnfRRmzqICFPPiWCPyIUpqrb704UFPeYlZ4VLt8bvX1GbHVDw","expires_in":3600}
================================================================================


================================================================================
>>> RESOURCE (as agent) REQUEST to http://127.0.0.1:8004/data-auth
================================================================================
GET http://127.0.0.1:8004/data-auth HTTP/1.1
Signature: sig1=:ZZneZeSzbj7NQvv_RDs4kjtwKVeXadHCVDWVPrR3kyIRujc_ghFeBJbpfbqH1bbaZbbVuIFvi_PMLuewAibvCw:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786273
Signature-Key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...
================================================================================


================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-auth HTTP/1.1
Host: 127.0.0.1:8004
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8004
signature: sig1=:ZZneZeSzbj7NQvv_RDs4kjtwKVeXadHCVDWVPrR3kyIRujc_ghFeBJbpfbqH1bbaZbbVuIFvi_PMLuewAibvCw:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786273
signature-key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58744 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
INFO:     127.0.0.1:58745 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58746 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
INFO:     127.0.0.1:58747 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 200
content-length: 212
content-type: application/json

[Body (212 bytes)]
{"message":"Access granted","data":"This is protected data (authorized)","scheme":"jwt","token_type":"auth+jwt","method":"GET","agent":"http://127.0.0.1:8002","agent_delegate":null,"scope":"data.read data.write"}
================================================================================

INFO:     127.0.0.1:58743 - "GET /data-auth HTTP/1.1" 200 OK

================================================================================
<<< DOWNSTREAM RESPONSE from http://127.0.0.1:8004/data-auth
================================================================================
HTTP/1.1 200 OK
content-length: 212
content-type: application/json
date: Mon, 19 Jan 2026 01:31:13 GMT
server: uvicorn

[Body (212 bytes)]
{"message":"Access granted","data":"This is protected data (authorized)","scheme":"jwt","token_type":"auth+jwt","method":"GET","agent":"http://127.0.0.1:8002","agent_delegate":null,"scope":"data.read data.write"}
================================================================================


✓ Resource 2 access granted
  Response: {
  "message": "Access granted",
  "data": "This is protected data (authorized)",
  "scheme": "jwt",
  "token_type": "auth+jwt",
  "method": "GET",
  "agent": "http://127.0.0.1:8002",
  "agent_delegate": null,
  "scope": "data.read data.write"
}


Exchanged token claims:
  iss: http://127.0.0.1:8005
  aud: http://127.0.0.1:8004
  agent: http://127.0.0.1:8002
  sub: None
  act: {
    "agent": "http://127.0.0.1:8001"
  }


  
```