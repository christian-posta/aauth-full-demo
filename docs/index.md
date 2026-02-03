---
layout: default
title: Documentation
permalink: /
---

<div class="hero">
  <h1>AAuth Demo Documentation</h1>
  <p>User-delegated AAuth flow, configuration, and multi-hop token exchange for the supply chain and market analysis agents.</p>
</div>

<div class="doc-cards">
  <a href="{{ '/user-delegated-aauth/' | relative_url }}" class="doc-card">
    <h3>User-Delegated AAuth Flow</h3>
    <p>Consent flow, auth tokens (<code>scheme=jwt</code>), resource tokens, and multi-hop token exchange from Backend → Supply Chain Agent → Market Analysis Agent.</p>
  </a>
  <a href="{{ '/aauth-configuration/' | relative_url }}" class="doc-card">
    <h3>AAuth Configuration</h3>
    <p>Environment variables for Backend, Supply Chain Agent, Market Analysis Agent, and Frontend; Keycloak setup; hostnames and ports.</p>
  </a>
</div>

<p style="margin-top: 2rem; color: var(--text-muted); font-size: 0.9375rem;">
  See also the repository README, SPEC.md, and each component's README (<code>backend/</code>, <code>supply-chain-agent/</code>, <code>market-analysis-agent/</code>) in the source.
</p>
