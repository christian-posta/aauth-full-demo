---
layout: default
title: Exploring AAuth for Agent Identity and Access Management (IAM)
---

# Exploring AAuth for Agent IAM


[Agent Auth](https://github.com/dickhardt/AAuth) (AAuth -- pronounced "AY-awth") is an [IETF draft paper for agent identity and access management](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/) from [Dick Hardt](https://github.com/dickhardt) who [authored OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) and co-author of [OAuth 2.1](https://github.com/oauth-wg/oauth-v2-1/blob/main/draft-ietf-oauth-v2-1.md). 

## Intro: Digging in to AAuth Flows

We have recently published a full [AAuth Protocol Explorer](https://aauth.dev) that walks you through, in detail, all of the resource access flows. 

![](./images/explorer.png)

## 🎉 Full Working Demo with Agent Bootstrap, Person Server, and Agentgateway

This set of resources walks you through set up and evaluation of a realistic AAuth implementation with Person Server, [Agentgateway](https://github.com/agentgateway/agentgateway), a component to turn [ANY resource into an AAuth resource](https://github.com/christian-posta/extauth-aauth-resource), and libraries to support AAuth in multiple languages (Java, Python, Rust, Go). 

![](./images/demo-flow.png)

The source code for this section can be found in GitHub: [https://github.com/christian-posta/aauth-full-demo](https://github.com/christian-posta/aauth-full-demo). 

This demo shows two different modes of accessing a resource: Mode 1 which is identity only access: ie, the resource can decide what policies to enable/enforce based on client identity. In the spec, this is known as [Identity Based resource access](https://explorer.aauth.dev/access/identity-based).  The other option is Mode 3 which requires the agent to present a valid auth token (aa-auth+jwt) which follows the 401/resoruce-token. In the spec, this is referred to as ["3 Party resource access"](https://explorer.aauth.dev/access/ps-managed). 

Agent identity comes from an Agent Provider and is issued through the [aa-agent+jwt token issuance](https://explorer.aauth.dev/signing/agent-tokens).

1. [AAuth with Keycloak and Agentgateway](install-aauth-keycloak.md)
2. [Agent Identity with aa-agent+jwt (Bootstrap)](agent-identity-jwks.md)
3. [Agent authorization (autonomous flow)](agent-authorization-autonomous.md)
4. [Agent authorization (user consent)](agent-authorization-on-behalf-of.md)
5. [Token Exchange for Auth propagation (OBO)](agent-token-exchange.md)
6. [Apply policy with AgentGateway](apply-policy-agentgateway.md)
7. [Clarification Chat on Authorization](clarification-chat-authorization.md)


## AAuth Implementation Resources

1. [Java Library](https://github.com/christian-posta/keycloak/tree/ceposta-aauth/services/src/main/java/org/keycloak/protocol/aauth/signing)
2. [Python Library](https://github.com/christian-posta/aauth-implementation/tree/main/aauth)
3. [Rust Library](https://github.com/christian-posta/agentgateway/tree/ceposta-aauth-rust/crates/aauth)
4. [Keycloak AAuth SPI](https://github.com/christian-posta/keycloak-aauth-extension)
5. [Agentgateway AAuth Impl](https://github.com/christian-posta/agentgateway/tree/ceposta-aauth-rust)
6. [Agentgateway AAuth Release](https://github.com/christian-posta/agentgateway/releases/tag/v0.11.4)
