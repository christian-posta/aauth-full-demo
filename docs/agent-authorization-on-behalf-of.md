---
layout: default
title: Agent authorization (on behalf of)
---

# Agent authorization (on behalf of)

[← Back to index](index.md)

things we need to do:

make sure to set up the consent scopes with the script
- with keycloak running, we need to do:
```bash
./keycloak/set_aauth_consent_attributes.sh 

==============================================
  AAuth Consent Attributes Configuration
==============================================

Keycloak: http://localhost:8080
Realm:    aauth-test

Connecting to Keycloak...

What would you like to do?
  1) Scopes only   - configure exact scope names (e.g. openid, profile, email)
  2) Prefixes only - configure scope prefixes (e.g. user., profile., email.)
  3) Both scopes and prefixes
  4) Use defaults for both
  5) View current scopes/prefixes
  6) Clear scopes and prefixes (set to empty)
  7) Quit (no changes)

Choice [1-7]: 
```
Choose `1` and then for the scope we need user consent for, add `supply-chain:optimize`

It should look like this:

```bash
Choice [1-7]: 1

--- Configure scopes ---
  Examples: openid, profile, email
  Default:  ["openid","profile","email"]

Enter scopes (comma-separated, or press Enter for default): supply-chain:optimize

Summary:
  Scopes:   [  "supply-chain:optimize"]
  Prefixes: ["user.","profile.","email."]

Apply these to Keycloak? [Y/n]: 
```

Hit ENTER to continue and you should see keycloak updated:

```bash
Applying to Keycloak...
✅ Successfully set AAuth consent attributes for realm 'aauth-test'!

Configured values:
  aauth.consent.required.scopes:         ["supply-chain:optimize"]
  aauth.consent.required.scope.prefixes: ["user.","profile.","email."]

Non-interactive usage:
  export AAUTH_CONSENT_SCOPES='["openid","profile","email"]'
  export AAUTH_CONSENT_PREFIXES='["user.","profile.","email."]'
  ./keycloak/set_aauth_consent_attributes.sh http://localhost:8080 aauth-test admin admin
```




restart the servers with user-consent
SCA:

```bash
uv run . --signature-scheme jwks --authorization-scheme user-delegated
```


Go back to UI (login/refresh if needed) and hit the Button "Optimize Laptop Supply Chain":




explain the relationship to OIDC

show JWTs with sub / agent 


Backend gets the 401, starts the auth flow, and Keycloak detects this is asking for scopes that require user cosnent, so send back the request token which triggers user consent flow in the Agent/UI:

```bash
INFO:aauth.tokens:🔐 401 from supply-chain-agent (url=http://supply-chain-agent.localhost:3000): headers={'date': 'Sat, 07 Feb 2026 16:56:35 GMT', 'server': 'uvicorn', 'agent-auth': 'httpsig; auth-token; resource_token="eyJhbGciOiJFZERTQSIsImtpZCI6InN1cHBseS1jaGFpbi1hZ2VudC1lcGhlbWVyYWwtMSIsInR5cCI6InJlc291cmNlK2p3dCJ9.eyJpc3MiOiJodHRwOi8vc3VwcGx5LWNoYWluLWFnZW50LmxvY2FsaG9zdDozMDAwIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9hYXV0aC10ZXN0IiwiYWdlbnQiOiJodHRwOi8vYmFja2VuZC5sb2NhbGhvc3Q6ODAwMCIsImFnZW50X2prdCI6IlVDaWE5dEpNV3lEMWZPMGlhV1YxV2NzQmRaQzIwb0E5MVZYLS1VY2NXM0UiLCJleHAiOjE3NzA0ODM2OTYsInNjb3BlIjoic3VwcGx5LWNoYWluOm9wdGltaXplIG1hcmtldC1hbmFseXNpczphbmFseXplIn0.jHesCOn3qIXke_aAe3VrIzS7RbLhW9_rMRfLNqVeMDC9YZl16a1RvOEELHiy0wXA-Cy7y3CUzW7t5N_FbxgiCA"; auth_server="http://localhost:8080/realms/aauth-test"', 'content-length': '22', 'content-type': 'text/plain; charset=utf-8'}
INFO:aauth.tokens:🔐 Received resource_token from 401 (supply-chain-agent): eyJhbGciOiJFZERTQSIsImtpZCI6InN1cHBseS1jaGFpbi1hZ2VudC1lcGhlbWVyYWwtMSIsInR5cCI6InJlc291cmNlK2p3dCJ9.eyJpc3MiOiJodHRwOi8vc3VwcGx5LWNoYWluLWFnZW50LmxvY2FsaG9zdDozMDAwIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9hYXV0aC10ZXN0IiwiYWdlbnQiOiJodHRwOi8vYmFja2VuZC5sb2NhbGhvc3Q6ODAwMCIsImFnZW50X2prdCI6IlVDaWE5dEpNV3lEMWZPMGlhV1YxV2NzQmRaQzIwb0E5MVZYLS1VY2NXM0UiLCJleHAiOjE3NzA0ODM2OTYsInNjb3BlIjoic3VwcGx5LWNoYWluOm9wdGltaXplIG1hcmtldC1hbmFseXNpczphbmFseXplIn0.jHesCOn3qIXke_aAe3VrIzS7RbLhW9_rMRfLNqVeMDC9YZl16a1RvOEELHiy0wXA-Cy7y3CUzW7t5N_FbxgiCA
INFO:     127.0.0.1:53276 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:53276 - "GET /jwks.json HTTP/1.1" 200 OK
INFO:aauth.tokens:🔐 Received request_token from auth server (user consent required): 6cd2d825-158b-4efb-93da-f4e73a499d8a.1770483396.NmNkMmQ4MjUtMTU4Yi00ZWZiLTkzZGEtZjRlNzNhNDk5ZDhhOjE3NzA0ODMzOTY6aHR0cDovL2JhY2tlbmQubG9jYWxob3N0OjgwMDA
INFO:     127.0.0.1:53268 - "POST /optimization/start HTTP/1.1" 200 OK
INFO:     127.0.0.1:53302 - "GET /.well-known/aauth-agent HTTP/1.1" 200 OK
INFO:     127.0.0.1:53302 - "GET /jwks.json HTTP/1.1" 200 OK
```

User is directed to review scope:

![](./images/user-consent.png)


supply chain ends up with this:

```bash
INFO:agent_executor:✅ AAuth signature verification successful
INFO:aauth.tokens:🔐 Received auth_token in request (HTTPSig scheme=jwt): eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiYXV0aCtqd3QiLCJraWQiIDogIjF2SGZlTWk5U0E4VTdWZlNKRTN3SnVTQklOZUhVeWpOY0pzZ2tYWWNHQlkifQ.eyJleHAiOjE3NzA0ODM3NjUsImlhdCI6MTc3MDQ4MzQ2NSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9hYXV0aC10ZXN0IiwiYXVkIjoiaHR0cDovL3N1cHBseS1jaGFpbi1hZ2VudC5sb2NhbGhvc3Q6MzAwMCIsInN1YiI6IjAwYjUxOWU4LWY0MDktNDIwMS04OTExLTFjYjQwOGU4YTA4MiIsImFnZW50IjoiaHR0cDovL2JhY2tlbmQubG9jYWxob3N0OjgwMDAiLCJjbmYiOnsiandrIjp7ImtpZCI6IkdmWHZZS3ZscktGb3V2S1JQdUFnbFJZX3RiTmJJTFpMRzJBaTJNd2l6bVUiLCJrdHkiOiJPS1AiLCJ1c2UiOiJzaWciLCJjcnYiOiJFZDI1NTE5IiwieCI6IklDSEVXYUwyRTBFaGJkU3F4eGZ5ZUY4RjF5WndiNEViQzJKQXZ0dl9ZR3cifX0sInNjb3BlIjoic3VwcGx5LWNoYWluOm9wdGltaXplIG1hcmtldC1hbmFseXNpczphbmFseXplIn0.NAsgPE4DHrS36m98J76QbsZHWj9EIYJzVg1mqa5IJv6xp6lRbsqYO7jnqodh5QV86yhrLpBWpVzyrSYm1LU9DJnh8VegIR9JWUwO-c9j4xdFIQLdDIAzCMalCUTWnC2E2dwZA1raaw3kxxJ1eKkIOWQqWRp-oeubHdtoqI2yJHbVZNs1VQ7YeajGygyEHFG3W7F1eWpt8TChF8sy5gvqvk5DPiHXRykyxpghK-klq4hzQACIAXoFhtBUo8zqYFtF_gtSkQPcs_CdNhjp5ksr-ZkyqpXQjhBmajaARNGoVxUtdAtVOyoz4wFSFwBTTYpFg-f4IrkjA-kwCE-_71UZ5A
INFO:agent_executor:🔐 Auth token detected in request (scheme=jwt)
INFO:httpx:HTTP Request: GET http://localhost:8080/realms/aauth-test/protocol/openid-connect/certs "HTTP/1.1 200 OK"
INFO:agent_executor:✅ Auth token verified successfully
INFO:agent_executor:✅ Authorization successful: auth_token verified for agent: http://backend.localhost:8000
INFO:agent_executor:🔐 Extracted upstream auth_token for token exchange (length: 1037)
INFO:agent_executor:🔐 Using AAuth JWKS signing for downstream agent calls
INFO:agent_executor:🔐 Upstream auth_token available for token exchange if needed
INFO:     127.0.0.1:53306 - "POST / HTTP/1.1" 200 OK
```

This is the token:

```json
{
  "exp": 1770483765,
  "iat": 1770483465,
  "iss": "http://localhost:8080/realms/aauth-test",
  "aud": "http://supply-chain-agent.localhost:3000",
  "sub": "00b519e8-f409-4201-8911-1cb408e8a082",
  "agent": "http://backend.localhost:8000",
  "cnf": {
    "jwk": {
      "kid": "GfXvYKvlrKFouvKRPuAglRY_tbNbILZLG2Ai2MwizmU",
      "kty": "OKP",
      "use": "sig",
      "crv": "Ed25519",
      "x": "ICHEWaL2E0EhbdSqxxfyeF8F1yZwb4EbC2JAvtv_YGw"
    }
  },
  "scope": "supply-chain:optimize market-analysis:analyze"
}
```



we should explain the token exchange step (or do this in another page?)
show JWTs with sub / agent / act

