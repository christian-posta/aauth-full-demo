---
layout: default
title: Exploring AAuth for Agent Identity and Access Management (IAM)
nav_order: 0
---

# Exploring AAuth for Agent IAM


[Agent Auth](https://github.com/dickhardt/AAuth) (AAuth -- pronounced "AY-awth") is an [IETF draft paper, part of the OAuth working group, that specifies a protocol for agent identity and access management](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/) from [Dick Hardt](https://github.com/dickhardt) who [authored OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) and co-author of [OAuth 2.1](https://github.com/oauth-wg/oauth-v2-1/blob/main/draft-ietf-oauth-v2-1.md). 

## Intro: Digging in to AAuth Flows

If you want a step by step guide through the AAuth protocol, I recommend you take a look at the [AAuth Protocol Explorer](https://explorer.aauth.dev). The explorer walks you through, in detail with all requests/responses/tokens, etc, all of the resource access flows. 

![](./images/explorer.png)

## 🎉 Full Working Demo with Agent Bootstrap, Person Server, and Agentgateway

AAuth is best understood with working code. 

This set of resources walks you through set up and evaluation of a realistic AAuth implementation with Agent Identity, Authorization, and Person Server attested flows. We leverage the [Python AAuth Library](https://github.com/christian-posta/aauth-python-library), [Agentgateway](https://github.com/agentgateway/agentgateway), and an AAuth resource proxy to turn [ANY resource into an AAuth resource](https://github.com/christian-posta/extauth-aauth-resource). 

![](./images/demo-flow.png)

The source code for this demo can be found in GitHub: [https://github.com/christian-posta/aauth-full-demo](https://github.com/christian-posta/aauth-full-demo). 

This demo covers two access modes. **Mode 1** (identity-based) — the resource verifies the agent's `aa-agent+jwt` and applies local policy; no 401 challenge and no auth token required. In the spec this is [Identity Based resource access](https://explorer.aauth.dev/access/identity-based). **Mode 3** (PS-managed / three-party) — the resource issues a 401 challenge with an `aa-resource+jwt`; the agent exchanges it at the Person Server for an `aa-auth+jwt` auth token and retries. In the spec this is [3-Party resource access](https://explorer.aauth.dev/access/ps-managed).

Agent identity in both modes comes from an `aa-agent+jwt` bootstrapped from the Person Server at startup. See [aa-agent+jwt token issuance](https://explorer.aauth.dev/bootstrap/self-hosted). Our implementation deviates slightly (allowed within the spec: bootstrap is non-normative). 

> **Run it end-to-end first.** See [`TEST.md`](https://github.com/christian-posta/aauth-full-demo/blob/main/TEST.md) for the quick-start: prerequisites, `./scripts/run-tests.sh all`, and troubleshooting tips. Each sub-guide below assumes those prerequisites are met.

1. [Install Agentgateway / Person Server / Agent Provider](install-aauth.md)
2. [Agent Identity with aa-agent+jwt (Bootstrap)](agent-identity-jwks.md)
3. [Agent authorization (autonomous flow)](agent-authorization-autonomous.md)
4. [Agent authorization (user consent)](agent-authorization-on-behalf-of.md)
5. [Apply policy with AgentGateway](apply-policy-agentgateway.md)


## AAuth Implementation Resources

The following open-source components are used in this demo:

1. [Python AAuth Library (`aauth`)](https://github.com/christian-posta/aauth-python-library) — request signing, key generation, and token helpers used by the Python agents and the backend (pinned as `aauth>=0.3.4`).
2. [Go AAuth Library](https://github.com/christian-posta/aauth-go-library) — Go implementation of AAuth signing and verification; consumed by `aauth-service` (the `extauth-aauth-resource` below) to validate agent tokens and proof-of-possession.
3. [AAuth Person Server](https://github.com/christian-posta/aauth-person-server) — reference Person Server that also acts as the Agent Provider: issues `aa-agent+jwt`, manages user consent, and issues `aa-auth+jwt`.
4. [ExtAuthz AAuth Resource (`aauth-service`)](https://github.com/christian-posta/extauth-aauth-resource) — Envoy ExtAuthz service that turns any HTTP / MCP / A2A resource into an AAuth resource (demo-tested release: [v0.0.1](https://github.com/christian-posta/extauth-aauth-resource/releases/tag/v0.0.1)).
5. [Agentgateway](https://github.com/agentgateway/agentgateway) — LLM / MCP / A2A gateway used as the AAuth policy enforcement point (demo-tested release: [v0.11.4](https://github.com/christian-posta/agentgateway/releases/tag/v0.11.4)).
6. [Demo source code](https://github.com/christian-posta/aauth-full-demo) — this repository, including the supply-chain and market-analysis agents, backend, scripts, and Agentgateway configs.
