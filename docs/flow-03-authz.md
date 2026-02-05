---
layout: default
title: Flow - Agent Authorizations
description: No identity, but TOFU
---

[← Back to index](index.md)

```bash
================================================================================
Autonomous Authorization Demo
================================================================================

This demo shows the complete autonomous authorization flow:
1. Agent requests resource (gets resource token challenge)
2. Agent presents resource token to auth server
3. Auth server issues auth token
4. Agent retries resource request with auth token
5. Resource validates auth token and grants access

Debug output is enabled by default.
================================================================================

Starting Agent...
Starting Resource...
Starting Auth Server...
Waiting for servers to start...
INFO:     Started server process [94912]
INFO:     Waiting for application startup.
INFO:     Started server process [94912]
INFO:     Waiting for application startup.
INFO:     Started server process [94912]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Application startup complete.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8003 (Press CTRL+C to quit)
INFO:     Uvicorn running on http://0.0.0.0:8001 (Press CTRL+C to quit)
INFO:     Uvicorn running on http://0.0.0.0:8002 (Press CTRL+C to quit)

================================================================================
Ready to start test. Press Enter to begin...
================================================================================


================================================================================
TEST 1: Autonomous Authorization Flow
================================================================================
Description: Agent requests protected resource, receives resource token challenge,
             obtains auth token from auth server, and successfully accesses resource.
================================================================================


================================================================================
>>> AGENT REQUEST to http://127.0.0.1:8002/data-auth
================================================================================
GET http://127.0.0.1:8002/data-auth HTTP/1.1
Signature: sig1=:ZMGGi5N61KL-AWkTbLZDPWRA3AUefyhCtOmQ-Wp7CF6IeIch6RpzAfatdOj3VoSGL-BAouXpMCViML8gvFH1Aw:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768785919
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
signature: sig1=:ZMGGi5N61KL-AWkTbLZDPWRA3AUefyhCtOmQ-Wp7CF6IeIch6RpzAfatdOj3VoSGL-BAouXpMCViML8gvFH1Aw:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768785919
signature-key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58645 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58646 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 401
agent-auth: httpsig; auth-token; resource_token="eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoi...
content-length: 22

[Body (22 bytes)]
Authorization required
================================================================================

INFO:     127.0.0.1:58644 - "GET /data-auth HTTP/1.1" 401 Unauthorized

================================================================================
<<< AGENT RESPONSE from http://127.0.0.1:8002/data-auth
================================================================================
HTTP/1.1 401 Unauthorized
agent-auth: httpsig; auth-token; resource_token="eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoi...
content-length: 22
date: Mon, 19 Jan 2026 01:25:19 GMT
server: uvicorn

[Body (22 bytes)]
Authorization required
================================================================================

INFO:     127.0.0.1:58647 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK

================================================================================
>>> AGENT REQUEST to http://127.0.0.1:8003/agent/token
================================================================================
POST http://127.0.0.1:8003/agent/token HTTP/1.1
Content-Digest: sha-256=:X4BI4dl2iOkMAnOAiyP0GgBX01OkmEmauc6Nm6DTbwE=:
Content-Type: application/x-www-form-urlencoded
Signature: sig1=:MYpXTXsAIXRUw8oUy70waxmtkbdKljMolYS6v_R7yeNUaly3mtE9NC01uF3KBCD4CfBoTBcuf3FoXAXF84bLCQ:
Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
Signature-Key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")

[Body (510 bytes)]
request_type=auth&resource_token=eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoicmVzb3VyY2Urand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDIiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDMiLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSIsImFnZW50X2prdCI6InpBa1JhRnBtSXhpN2tIRVNxem9ScjNpaG1LUEpIQmVqY0hyek9VcVRlR28iLCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg2NTE5fQ.JxycOxkDV2bL6xkKD8PT5tkZ0kOeYj7iSuwL6G0zfc0TTsb853vIcFf_DWFrthxYkwet04l5iZ3LemDRFwmwDQ&redirect_uri=http://127.0.0.1:8001/callback
================================================================================


================================================================================
>>> AUTH SERVER REQUEST received
================================================================================
POST /agent/token HTTP/1.1
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
content-digest: sha-256=:X4BI4dl2iOkMAnOAiyP0GgBX01OkmEmauc6Nm6DTbwE=:
content-length: 510
content-type: application/x-www-form-urlencoded
host: 127.0.0.1:8003
signature: sig1=:MYpXTXsAIXRUw8oUy70waxmtkbdKljMolYS6v_R7yeNUaly3mtE9NC01uF3KBCD4CfBoTBcuf3FoXAXF84bLCQ:
signature-input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
signature-key: sig1=(scheme=jwks id="http://127.0.0.1:8001" kid="key-1" well-known="aauth-agent")
user-agent: python-httpx/0.28.1

[Body (510 bytes)]
request_type=auth&resource_token=eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoicmVzb3VyY2Urand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDIiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDMiLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSIsImFnZW50X2prdCI6InpBa1JhRnBtSXhpN2tIRVNxem9ScjNpaG1LUEpIQmVqY0hyek9VcVRlR28iLCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg2NTE5fQ.JxycOxkDV2bL6xkKD8PT5tkZ0kOeYj7iSuwL6G0zfc0TTsb853vIcFf_DWFrthxYkwet04l5iZ3LemDRFwmwDQ&redirect_uri=http://127.0.0.1:8001/callback
================================================================================

INFO:     127.0.0.1:58649 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58650 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58651 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58652 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58653 - "GET /.well-known/aauth-resource HTTP/1.1" 200 OK
INFO:     127.0.0.1:58654 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< AUTH SERVER RESPONSE
================================================================================
HTTP/1.1 200 OK
Content-Type: application/json

[Body]
{
  "auth_token": "eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDMiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDIiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoidjR3MW5mZVUySVY5TWk3Tl9wTERiQnZOTWVyV2hsTXdhZ0YxRHdfN3dYUSIsImtpZCI6ImtleS0xIn19LCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg5NTE5LCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSJ9.7Tktsi-oQz-ygO1IzePYq-xA73pYqakXynMCttdIiIaK0pULAEtg9zJlveGs6NYtJugqFl-3aA7LeNnlQj75Bg",
  "expires_in": 3600,
  "token_type": "Bearer"
}
================================================================================

INFO:     127.0.0.1:58648 - "POST /agent/token HTTP/1.1" 200 OK

================================================================================
<<< AGENT RESPONSE from http://127.0.0.1:8003/agent/token
================================================================================
HTTP/1.1 200 OK
content-length: 545
content-type: application/json
date: Mon, 19 Jan 2026 01:25:19 GMT
server: uvicorn

[Body (545 bytes)]
{"auth_token":"eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDMiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDIiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoidjR3MW5mZVUySVY5TWk3Tl9wTERiQnZOTWVyV2hsTXdhZ0YxRHdfN3dYUSIsImtpZCI6ImtleS0xIn19LCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg5NTE5LCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSJ9.7Tktsi-oQz-ygO1IzePYq-xA73pYqakXynMCttdIiIaK0pULAEtg9zJlveGs6NYtJugqFl-3aA7LeNnlQj75Bg","expires_in":3600,"token_type":"Bearer"}
================================================================================


================================================================================
>>> AGENT REQUEST to http://127.0.0.1:8002/data-auth
================================================================================
GET http://127.0.0.1:8002/data-auth HTTP/1.1
Signature: sig1=:7iiclCyzY7xfitBNgWZBAJOM4JmmmNtyoE7JaYwOXSej-OZg7Mx9FMHtLTau5tGs-NEtvJKQWmJndCfPbhNuDw:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768785919
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
signature: sig1=:7iiclCyzY7xfitBNgWZBAJOM4JmmmNtyoE7JaYwOXSej-OZg7Mx9FMHtLTau5tGs-NEtvJKQWmJndCfPbhNuDw:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768785919
signature-key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58656 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
INFO:     127.0.0.1:58657 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58658 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
INFO:     127.0.0.1:58659 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 200
content-length: 212
content-type: application/json

[Body (212 bytes)]
{"message":"Access granted","data":"This is protected data (authorized)","scheme":"jwt","token_type":"auth+jwt","method":"GET","agent":"http://127.0.0.1:8001","agent_delegate":null,"scope":"data.read data.write"}
================================================================================

INFO:     127.0.0.1:58655 - "GET /data-auth HTTP/1.1" 200 OK

================================================================================
<<< AGENT RESPONSE from http://127.0.0.1:8002/data-auth
================================================================================
HTTP/1.1 200 OK
content-length: 212
content-type: application/json
date: Mon, 19 Jan 2026 01:25:19 GMT
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
  "agent_jkt": "zAkRaFpmIxi7kHESqzoRr3ihmKPJHBejcHrzOUqTeGo",
  "scope": "data.read data.write",
  "exp": 1768786519
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
      "x": "v4w1nfeU2IV9Mi7N_pLDbBvNMerWhlMwagF1Dw_7wXQ",
      "kid": "key-1"
    }
  },
  "scope": "data.read data.write",
  "exp": 1768789519,
  "agent": "http://127.0.0.1:8001"
}
================================================================================

```