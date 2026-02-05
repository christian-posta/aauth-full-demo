---
layout: default
title: Pseudonymous Agent
description: No identity, but TOFU
---

# Pseudonymous Agent 

[← Back to index](index.md)




## HWK (Header Web Key) Scheme

Pseudonymous authentication in AAuth uses the **Header Web Key (HWK)** scheme (`scheme=hwk`). The signing key is included in the request headers rather than resolved from a well-known URL. The resource verifies the signature using the key from the header but has no way to correlate requests to a persistent agent identity.

| Scheme | Identity | Use case |
|--------|----------|----------|
| `hwk`  | Pseudonymous | Lightweight verification, rate limiting, abuse prevention |
| `jwks` | Identified   | Verified agent identity via published keys |

## Configuration

In this demo, agents and the backend can be configured for HWK (pseudonymous) or JWKS (identified) via `AAUTH_SIGNATURE_SCHEME`:

- `hwk` – Header Web Key (pseudonymous)
- `jwks` – Identified agent with published JWKS

See [Agent Identity with JWKS](agent-identity-jwks.md) for the identified agent flow.

## Run the components

Run each component in a separate terminal. From each directory:

<style>
.run-tabs { margin: 1.5em 0; border: 1px solid #eaecef; border-radius: 6px; overflow: hidden; }
.run-tabs input { display: none; }
.run-tabs .tab-labels { display: flex; flex-wrap: wrap; background: #f6f8fa; border-bottom: 1px solid #eaecef; }
.run-tabs .tab-labels label { padding: 0.5em 1em; cursor: pointer; font-size: 0.9em; margin: 0; }
.run-tabs .tab-labels label:hover { background: #eaecef; }
.run-tabs input:nth-of-type(1):checked ~ .tab-labels label:nth-of-type(1),
.run-tabs input:nth-of-type(2):checked ~ .tab-labels label:nth-of-type(2),
.run-tabs input:nth-of-type(3):checked ~ .tab-labels label:nth-of-type(3),
.run-tabs input:nth-of-type(4):checked ~ .tab-labels label:nth-of-type(4) { background: #fff; border-bottom: 1px solid #fff; margin-bottom: -1px; font-weight: 600; }
.run-tabs .tab-content { display: none; padding: 1em; background: #fff; }
.run-tabs #tab-backend:checked ~ #content-backend,
.run-tabs #tab-agentgateway:checked ~ #content-agentgateway,
.run-tabs #tab-supply-chain:checked ~ #content-supply-chain,
.run-tabs #tab-market-analysis:checked ~ #content-market-analysis { display: block; }
.run-tabs .tab-content pre { margin: 0; }
</style>

<div class="run-tabs">
  <input type="radio" name="run-tabs" id="tab-backend" checked>
  <input type="radio" name="run-tabs" id="tab-agentgateway">
  <input type="radio" name="run-tabs" id="tab-supply-chain">
  <input type="radio" name="run-tabs" id="tab-market-analysis">
  <div class="tab-labels">
    <label for="tab-backend">Backend</label>
    <label for="tab-agentgateway">Agentgateway</label>
    <label for="tab-supply-chain">Supply-chain-agent</label>
    <label for="tab-market-analysis">Market-analysis</label>
  </div>
  <div class="tab-content" id="content-backend">
    <p>From the <code>backend</code> directory:</p>
    <pre><code>
      > uv run . --signature-scheme hwk
    </code></pre>
  </div>
  <div class="tab-content" id="content-agentgateway">
    <p>From the <code>agentgateway</code> directory:</p>
    <pre><code>
      > agentgateway -f agentgateway/config.yaml.hwk
    </code></pre>
  </div>
  <div class="tab-content" id="content-supply-chain">
    <p>From the <code>supply-chain-agent</code> directory:</p>
    <pre><code>
      > cp env.hwk .env
      > uv run .
    </code></pre>
  </div>
  <div class="tab-content" id="content-market-analysis">
    <p>From the <code>market-analysis-agent</code> directory:</p>
    <pre><code>
      > cp env.hwk .env
      > uv run .
    </code></pre>
  </div>
</div>

## Progressive Authentication

Resources use the `Agent-Auth` response header to request different authentication levels. Pseudonymous signatures satisfy the lowest level of proof—useful for:

- Allowing signed traffic while blocking unsigned abuse
- Progressive rate limiting (stricter for unsigned, more lenient for signed)
- Avoiding registration bottlenecks in dynamic agent ecosystems

---
