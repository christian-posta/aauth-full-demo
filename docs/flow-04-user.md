---
layout: default
title: Agent Authorization With User Consent
description: No identity, but TOFU
---

[← Back to index](index.md)

```bash
================================================================================
>>> AGENT REQUEST to https://important.resource.com/data-auth
================================================================================
GET https://important.resource.com/data-auth HTTP/1.1
Signature: sig1=:yNg83RIDMM7dnCJXGig_LrBskrbHtlTFDzCpMBQgtn1oELS1c4QNhH30rboOuGpDLgjaFx6Ut14n2gzWyV26DA:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786017
Signature-Key: sig1=(scheme=jwks id="https://agent.supply-chain.com" kid="key-1" well-known="aauth-agent")
================================================================================
```

Resource sees:

```bash
================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-auth HTTP/1.1
Host: 127.0.0.1:8002
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8002
signature: sig1=:yNg83RIDMM7dnCJXGig_LrBskrbHtlTFDzCpMBQgtn1oELS1c4QNhH30rboOuGpDLgjaFx6Ut14n2gzWyV26DA:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786017
signature-key: sig1=(scheme=jwks id="https://agent.supply-chain.com" kid="key-1" well-known="aauth-agent")
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58663 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58664 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 401
agent-auth: httpsig; auth-token; resource_token="eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoi...
content-length: 22

[Body (22 bytes)]
Authorization required
================================================================================

INFO:     127.0.0.1:58662 - "GET /data-auth HTTP/1.1" 401 Unauthorized
```

Agent sees:

```bash
================================================================================
<<< AGENT RESPONSE from https://important.resource.com/data-auth
================================================================================
HTTP/1.1 401 Unauthorized
agent-auth: httpsig; auth-token; resource_token="eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoi...
content-length: 22
date: Mon, 19 Jan 2026 01:26:57 GMT
server: uvicorn

[Body (22 bytes)]
Authorization required
================================================================================
```

Agent calls auth server:

```bash
INFO:     127.0.0.1:58665 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK

================================================================================
>>> AGENT REQUEST to https://auth-server.com/agent/token
================================================================================
POST https://auth-server.com/agent/token HTTP/1.1
Content-Digest: sha-256=:rMyTWCblP3KXnWkI2KGnDVqj91ETqvcEUuzSrXChi+c=:
Content-Type: application/x-www-form-urlencoded
Signature: sig1=:ICv_zjE12EOoEOSKofQR9R3-IoRL7TM0DEc2Q8cJubwoRnbWvFNUDQQFiVizugLFeTAmBQ4JqRGv2qLpQO8GBw:
Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
Signature-Key: sig1=(scheme=jwks id="https://agent.supply-chain.com" kid="key-1" well-known="aauth-agent")

[Body (510 bytes)]
request_type=auth&resource_token=eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoicmVzb3VyY2Urand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDIiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDMiLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSIsImFnZW50X2prdCI6IjRSNHpUX1R1c0RBOEFKbjJ4TUQzdzk3YUpYTm5vQnVLRlhIQVdiT3ZvclkiLCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg2NjE3fQ.xKqgqQ3C4P3y7qWcqeTgfJIIx_Jkp5qGbogN2r0mEOq8Nug4okRcfb1jWKlXm9HRveuky9xvdOrQCg-3nma-Ag&redirect_uri=https://agent.supply-chain.com/callback
================================================================================
```

Auth server sees: 

```bash
================================================================================
>>> AUTH SERVER REQUEST received
================================================================================
POST /agent/token HTTP/1.1
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
content-digest: sha-256=:rMyTWCblP3KXnWkI2KGnDVqj91ETqvcEUuzSrXChi+c=:
content-length: 510
content-type: application/x-www-form-urlencoded
host: 127.0.0.1:8003
signature: sig1=:ICv_zjE12EOoEOSKofQR9R3-IoRL7TM0DEc2Q8cJubwoRnbWvFNUDQQFiVizugLFeTAmBQ4JqRGv2qLpQO8GBw:
signature-input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
signature-key: sig1=(scheme=jwks id="https://agent.supply-chain.com" kid="key-1" well-known="aauth-agent")
user-agent: python-httpx/0.28.1

[Body (510 bytes)]
request_type=auth&resource_token=eyJhbGciOiJFZERTQSIsImtpZCI6InJlc291cmNlLWtleS0xIiwidHlwIjoicmVzb3VyY2Urand0In0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDIiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDMiLCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSIsImFnZW50X2prdCI6IjRSNHpUX1R1c0RBOEFKbjJ4TUQzdzk3YUpYTm5vQnVLRlhIQVdiT3ZvclkiLCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg2NjE3fQ.xKqgqQ3C4P3y7qWcqeTgfJIIx_Jkp5qGbogN2r0mEOq8Nug4okRcfb1jWKlXm9HRveuky9xvdOrQCg-3nma-Ag&redirect_uri=https://agent.supply-chain.com/callback
================================================================================

INFO:     127.0.0.1:58667 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58668 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58669 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58670 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58671 - "GET /.well-known/aauth-resource HTTP/1.1" 200 OK
INFO:     127.0.0.1:58672 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< AUTH SERVER RESPONSE
================================================================================
HTTP/1.1 200 OK
Content-Type: application/json

[Body]
{
  "request_token": "kgJ04U2x_0tIBAddXd5I_LTnUMow6dWnMTjkEPuY1Y4",
  "expires_in": 600
}
================================================================================

INFO:     127.0.0.1:58666 - "POST /agent/token HTTP/1.1" 200 OK
```

Note that the auth server is the one who decides that the user is needed for consent for this flow. It returns an request token similar to OAuth PAR. 

Agent sees:

```bash
================================================================================
<<< AGENT RESPONSE from https://auth-server.com/agent/token
================================================================================
HTTP/1.1 200 OK
content-length: 80
content-type: application/json
date: Mon, 19 Jan 2026 01:26:57 GMT
server: uvicorn

[Body (80 bytes)]
{"request_token":"kgJ04U2x_0tIBAddXd5I_LTnUMow6dWnMTjkEPuY1Y4","expires_in":600}
================================================================================

INFO:     127.0.0.1:58673 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
```

Agent puts user into consent flow:

```bash
================================================================================
CONSENT REQUIRED
================================================================================

Please open the following URL in your browser:

  https://auth-server.com/agent/auth?request_token=kgJ04U2x_0tIBAddXd5I_LTnUMow6dWnMTjkEPuY1Y4&redirect_uri=https://agent.supply-chain.com/callback

After granting consent, the agent will automatically exchange the code.
Waiting for authorization code...
================================================================================

INFO:     127.0.0.1:58674 - "GET /agent/auth?request_token=kgJ04U2x_0tIBAddXd5I_LTnUMow6dWnMTjkEPuY1Y4&redirect_uri=https://agent.supply-chain.com/callback HTTP/1.1" 200 OK
INFO:     127.0.0.1:58674 - "GET /favicon.ico HTTP/1.1" 404 Not Found
INFO:     127.0.0.1:58675 - "POST /agent/auth HTTP/1.1" 303 See Other
INFO:     127.0.0.1:58675 - "GET /agent/auth?request_token=kgJ04U2x_0tIBAddXd5I_LTnUMow6dWnMTjkEPuY1Y4&redirect_uri=https://agent.supply-chain.com/callback HTTP/1.1" 200 OK
INFO:     127.0.0.1:58676 - "POST /agent/auth HTTP/1.1" 303 See Other
INFO:     127.0.0.1:58678 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
```

Once approved by user, access_code gets sent to Auth server:

```bash
================================================================================
>>> AUTH SERVER REQUEST received
================================================================================
POST /agent/token HTTP/1.1
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
content-digest: sha-256=:iW1aTTCfubZKzu+4a8LoxYXIVEX0av0ii09u0ybxS1A=:
content-length: 110
content-type: application/x-www-form-urlencoded
host: 127.0.0.1:8003
signature: sig1=:qrlfQIgWSZtk5ret60dsdW-nIIjbM9S_nOO4dq8Mxs1hfnv0UZf-EZVOYB8E7QBD1J0QmQbwt-6CyJyzN8BoAg:
signature-input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=176...
signature-key: sig1=(scheme=jwks id="https://agent.supply-chain.com" kid="key-1" well-known="aauth-agent")
user-agent: python-httpx/0.28.1

[Body (110 bytes)]
request_type=code&code=3oyoQOpk9Mn1caCjVoJ-ibMfIpyRzBKwV2A5XPCuFGk&redirect_uri=https://agent.supply-chain.com/callback
================================================================================

INFO:     127.0.0.1:58680 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58681 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58682 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:58683 - "GET /jwks.json HTTP/1.1" 200 OK
```

Auth server approves request based on user consent and returns access token (and potentially refresh tokens)



```bash
================================================================================
<<< AUTH SERVER RESPONSE
================================================================================
HTTP/1.1 200 OK
Content-Type: application/json

[Body]
{
  "auth_token": "eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDMiLCJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDIiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiVXNSZF9lMExxOFdVNXVZRWtsb3d5cWVfRFNhRmZCOWZqbm5fX0R3V0Y2RSIsImtpZCI6ImtleS0xIn19LCJzY29wZSI6ImRhdGEucmVhZCBkYXRhLndyaXRlIiwiZXhwIjoxNzY4Nzg5NjQ1LCJhZ2VudCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMSIsInN1YiI6InRlc3R1c2VyIn0.EaktmXUYU6cW3chTfPnwNWRcF-kP0BlbMmCK6mOvSfERFeiGLgxtmJM8F9NmSh-_57kjmGQbJrV74QvlvEJgAw",
  "expires_in": 3600,
  "token_type": "Bearer"
}
================================================================================

INFO:     127.0.0.1:58679 - "POST /agent/token HTTP/1.1" 200 OK
INFO:     127.0.0.1:58677 - "GET /callback?code=3oyoQOpk9Mn1caCjVoJ-ibMfIpyRzBKwV2A5XPCuFGk HTTP/1.1" 200 OK
```

Agent can now take this JWT/access_token and call the resource again:


```bash
================================================================================
>>> AGENT REQUEST to https://important.resource.com/data-auth
================================================================================
GET https://important.resource.com/data-auth HTTP/1.1
Signature: sig1=:yMTf_qgsX8ouHj7D5N-NGXVpq8UAPaz12MhkQoRJwAsPBwsHc1NcTRXuo2KkicCLG03fzv-HWJd0Zo0bci4aCg:
Signature-Input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786045
Signature-Key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...
================================================================================
```

Resource now sees request that is identified and has proper authorization and consent from the user:

```bash
================================================================================
>>> RESOURCE REQUEST received
================================================================================
GET /data-auth HTTP/1.1
Host: 127.0.0.1:8002
accept: */*
accept-encoding: gzip, deflate
connection: keep-alive
host: 127.0.0.1:8002
signature: sig1=:yMTf_qgsX8ouHj7D5N-NGXVpq8UAPaz12MhkQoRJwAsPBwsHc1NcTRXuo2KkicCLG03fzv-HWJd0Zo0bci4aCg:
signature-input: sig1=("@method" "@authority" "@path" "signature-key");created=1768786045
signature-key: sig1=(scheme=jwt jwt="eyJhbGciOiJFZERTQSIsImtpZCI6ImF1dGgta2V5LTEiLCJ0eXAiOiJhdXRoK2p3dCJ9.eyJpc3...
user-agent: python-httpx/0.28.1
================================================================================

INFO:     127.0.0.1:58685 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
INFO:     127.0.0.1:58686 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:     127.0.0.1:58687 - "GET /.well-known/aauth-issuer HTTP/1.1" 200 OK
INFO:     127.0.0.1:58688 - "GET /jwks.json HTTP/1.1" 200 OK

================================================================================
<<< RESOURCE RESPONSE
================================================================================
HTTP/1.1 200
content-length: 212
content-type: application/json

[Body (212 bytes)]
{"message":"Access granted","data":"This is protected data (authorized)","scheme":"jwt","token_type":"auth+jwt","method":"GET","agent":"https://agent.supply-chain.com","agent_delegate":null,"scope":"data.read data.write"}
================================================================================

INFO:     127.0.0.1:58684 - "GET /data-auth HTTP/1.1" 200 OK
```

```bash
================================================================================
<<< AGENT RESPONSE from https://important.resource.com/data-auth
================================================================================
HTTP/1.1 200 OK
content-length: 212
content-type: application/json
date: Mon, 19 Jan 2026 01:27:25 GMT
server: uvicorn

[Body (212 bytes)]
{"message":"Access granted","data":"This is protected data (authorized)","scheme":"jwt","token_type":"auth+jwt","method":"GET","agent":"https://agent.supply-chain.com","agent_delegate":null,"scope":"data.read data.write"}
================================================================================
```

Inspecting the tokens (though, should do this maybe inline?)

```bash
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
  "iss": "https://important.resource.com",
  "aud": "https://auth-server.com",
  "agent": "https://agent.supply-chain.com",
  "agent_jkt": "4R4zT_TusDA8AJn2xMD3w97aJXNnoBuKFXHAWbOvorY",
  "scope": "data.read data.write",
  "exp": 1768786617
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
  "iss": "https://auth-server.com",
  "aud": "https://important.resource.com",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "UsRd_e0Lq8WU5uYEklowyqe_DSaFfB9fjnn__DwWF6E",
      "kid": "key-1"
    }
  },
  "scope": "data.read data.write",
  "exp": 1768789645,
  "agent": "https://agent.supply-chain.com",
  "sub": "testuser"
}
================================================================================
```