---
layout: default
title: Exploring AAuth for Agent Identity and Access Management (IAM)
---

# Exploring AAuth for Agent IAM

[Agent Auth](https://github.com/dickhardt/agent-auth) (AAuth -- pronounced "AY-awth") is an exploratory spec for agent identity and access management from [Dick Hardt](https://github.com/dickhardt) who [authored OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) and co-author of [OAuth 2.1](https://github.com/oauth-wg/oauth-v2-1/blob/main/draft-ietf-oauth-v2-1.md). 

## Intro: Digging in to AAuth Flows

This set of resources is intended to help you understand the AAuth protocol in concrete detail. It is not a specification (see [AAuth](https://github.com/dickhardt/agent-auth) for the evolution of that). This is specificatlly a more detailed review of the spec with examples (as a result of me implementing this). 

This section walks through various flows with detailed Header/Payload examples so the sequence diagrams from the AAuth exploratory draft are illustrated concretely. 

The source code for this section can be found on GitHub: [https://github.com/christian-posta/aauth-implementation](https://github.com/christian-posta/aauth-implementation)

1. [Header Web Key (HWK) for Pseudonymous Access](flow-01-hwk.md)
2. [Json Web Keys (JWKS) for Identified Access / Agent Identity](flow-02-jwks.md)
4. [Identified Agent Authorization](flow-03-authz.md)
4. [User Consent with Identified Access with Authorization](flow-04-user.md)
5. [Authorization Token Exchange](flow-05-token-ex.md)
6. [Delegated Agent Identity](flow-06-delegated.md)


## Full Working Demo with Keycloak and Agentgateway (WIP)

> 🚧 **Work in Progress**
> This demo section is under active development and will be available in the next few days.

This set of resources walks you through set up and evaluation of a realistic AAuth implementation with Identity Provider (Keycloak), Agentgateway, and libraries to support AAuth in multiple languages (Java, Python, Rust). 

The source code for this section can be found in GitHub: [https://github.com/christian-posta/aauth-full-demo](https://github.com/christian-posta/aauth-full-demo)

1. AAuth with Keycloak and Agentgateway
2. Agent Identity with JWKS
3. Agent authorization (autonomous flow)
4. Agent authorization (user consent)
5. Token Exchange for Auth propagation (OBO)
6. Apply policy with AgentGateway


## AAuth Implementation Resources

1. [Java Library](https://github.com/christian-posta/keycloak/tree/ceposta-aauth/services/src/main/java/org/keycloak/protocol/aauth/signing)
2. [Python Library](https://github.com/christian-posta/aauth-implementation/tree/main/aauth)
3. [Rust Library](https://github.com/christian-posta/agentgateway/tree/ceposta-aauth-rust/crates/aauth)
4. [Keycloak AAuth SPI](https://github.com/christian-posta/keycloak-aauth-extension)
5. [Agentgateway AAuth Impl](https://github.com/christian-posta/agentgateway/tree/ceposta-aauth-rust)
6. [Agentgateway AAuth Release](https://github.com/christian-posta/agentgateway/releases/tag/v0.11.3)
