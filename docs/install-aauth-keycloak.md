---
layout: default
title: AAuth with Keycloak and Agentgateway
---

# AAuth with Keycloak, Agentgateway, and Jaeger

[← Back to index](index.md)

<!-- Add content here -->

To prove out some of the AAuth patterns, I have implemented [AAuth in Keycloak](https://github.com/christian-posta/keycloak-aauth-extension) using a custom extension and in Agentgateway. Basically, you can download Keycloak, install the AAuth custom extension, and you have AAuth available for exploration and the rest of the demo in this guide. [Agentgateway](https://agentgateway.dev) is an LLM/MCP/A2A gateway that can be used to [introspect AAuth messages](https://github.com/christian-posta/agentgateway/releases/tag/v0.11.3), verify signatures, log them, send them to distributed tracing engines, and ultimately apply agent-based identity traffic and security policy. 

This guide will walk you through setup of Keycloak and Agentgateway so we can dig in for the rest of the demo. 

# AAuth on Keycloak

The AAuth extension is built on [Keycloak 26.2.5](https://www.keycloak.org/archive/downloads-26.2.5.html). [Download Keycloak](https://github.com/keycloak/keycloak/releases/tag/26.2.5) 26.2.5 for your environment and unpack it:


```bash
# Download Keycloak 26.2.5 release tarball
curl -LO https://github.com/keycloak/keycloak/releases/download/26.2.5/keycloak-26.2.5.tar.gz

# Unpack the tarball
tar -xzf keycloak-26.2.5.tar.gz

# The extracted directory will be 'keycloak-26.2.5'
cd keycloak-26.2.5

```

Now let's [download the AAuth extension](https://github.com/christian-posta/keycloak-aauth-extension) and install it to Keycloak in the `providers` folder:


```bash
# Download the AAuth extension JAR from the GitHub release
curl -LO https://github.com/christian-posta/keycloak-aauth-extension/releases/download/v1.0.2/keycloak-aauth-extension-1.0.0.jar

# Copy the JAR file into the Keycloak 'providers' directory
mv keycloak-aauth-extension-1.0.0.jar providers/
```

Now the AAuth extension is prepared, but we need to now configure Keycloak to know about it. From the root of the downloaded folder, you can run:

```bash
./bin/kc.sh build
```

To verify that the extension is installed, run the `show-config` command and notice `keycloak-aauth-extension`:

```bash
./bin/kc.sh show-config

Current Mode: production
Current Configuration:
	kc.log-level-org.infinispan.transaction.lookup.JBossStandaloneJTAManagerLookup =  WARN (classpath application.properties)
	kc.log-level-io.quarkus.config =  off (classpath application.properties)
	kc.log-console-output =  default (classpath application.properties)
	kc.provider.file.keycloak-aauth-extension-1.0.0.jar.last-modified =  1770216306403 (Persisted)
	kc.log-level-io.quarkus.hibernate.orm.deployment.HibernateOrmProcessor =  warn (classpath application.properties)
	kc.optimized =  true (Persisted)
	kc.version =  26.2.5 (SysPropConfigSource)
	kc.log-level-org.jboss.resteasy.resteasy_jaxrs.i18n =  WARN (classpath application.properties)
	kc.log-level-io.quarkus.arc.processor.BeanArchives =  off (classpath application.properties)
	kc.log-level-io.quarkus.deployment.steps.ReflectiveHierarchyStep =  error (classpath application.properties)
	kc.log-level-io.quarkus.arc.processor.IndexClassLookupUtils =  off (classpath application.properties)
	kc.log-level-org.hibernate.engine.jdbc.spi.SqlExceptionHelper =  off (classpath application.properties)
```

Now let's run Keycloak with a default `admin/admin` username and password:

```bash
# Start Keycloak in development mode with default admin username/password
# Start with debug logging on aauth: --log-level=org.keycloak.protocol.aauth:DEBUG

./bin/kc.sh start-dev --bootstrap-admin-username=admin --bootstrap-admin-password=admin 
```


Navigate to `http://localhost:8080` and login with `admin/admin`.


You can either set up the realm / client / users manually, or use a script in the `keycloak` dir of the [demo source code](https://github.com/christian-posta/aauth-full-demo).

```bash
./keycloak/configure-keycloak.sh
```

If you prefer to set up manually, you can create a realm called `aauth-test` and the following clients and users in that realm (for the demos in the rest of this guide)


*OAuth clien*t `supply-chain-ui`
* Redirect URIs: `http://localhost:3050/*`
* Web origins: `http://localhost:3050`
* Standard flow (authorization code) enabled
* Direct access grants (resource owner password) enabled
* Public client (no client secret, suitable for the SPA)


*Username*: `mcp-user`
* Password: `user123`
* Email: `mcp@user.com`
* First name: `Mcp`
* Last name: `User`
* Email verified: true (no verification required)

Test whether the token endpoint is available:


```bash
curl -X POST http://localhost:8080/realms/aauth-test/protocol/aauth/agent/token

{"error":"invalid_request","error_description":"Agent identity not found. Request must be signed with HTTPSig."}%
```


# AAuth with Agentgateway

Agentgateway is an opensource LLM, MCP, and A2A gateway hosted as part of the Linux Foundation. It focuses on implementing the missing pieces not found in traditional API gateways to support MCP and Agent workloads. The project emphasizes enterprise-grade security, observability, resiliency, reliability, and multi-tenancy features. Agentgateway is built to be the most performant, reliable, and mature LLM/MCP gateway on the market.

I have [built an implementation of the AAuth HTTPSig verification](https://github.com/christian-posta/agentgateway) into Agentgateawy on my branch. This is for experimentation only. For a produection Agentgateway visit the repo [https://github.com/agentgateway/agentgateway](https://github.com/agentgateway/agentgateway) 

With the AAuth build, you can:

- verify message signatures for AAuth requests
- enforce minimum thresholds of authentication (pseudonymous, identified, authorized)
- log and trace details of the aauth request
- enforce allow/deny policy based on agent identity (`aa-agent+jwt`, `aa-auth+jwt`)
- enforce rate limit policy based on authentication levels

To get started with Agentgateway for this AAuth demo, you can [download the release](https://github.com/christian-posta/agentgateway/releases/tag/v0.11.3) and configure it with the config.yaml in this source code repo.

```bash
# Download Agentgateway binary (for macOS amd64) and rename to 'agentgateway'
curl -L -o agw https://github.com/christian-posta/agentgateway/releases/download/v0.11.4/agentgateway-darwin-amd64
chmod +x agw
```

Now you can run agentgateway with configurations for this demo:

```bash
./agw -f ./agentgateway/config.yaml
```

This configuration will rely on local routing by hostname. You can add this to your /etc/hosts:

```bash
127.0.0.1   backend.localhost
127.0.0.1   supply-chain-agent.localhost
127.0.0.1   market-analysis-agent.localhost
```


# AAuth with Jaeger Distributed Tracing

The Agentgateway (and the agents in this demo) is configured to send tracing spans to http://localhost:4317. We can see the full token AAuth token flow in Jaeger. We can start Jaeger with the following:

```bash
./agentgateway/run-jaeger.sh
```


At this point we can [proceed with the demo](./agent-identity-jwks.md). 

> **Important — Person Server as Agent Server:** The Person Server (`http://127.0.0.1:8765`) plays a dual role in this demo. It is the **Agent Server** that issues `aa-agent+jwt` tokens to each agent at startup, AND it is the **Person Server** that manages user consent and issues `aa-auth+jwt` auth tokens. Keycloak is used for OIDC authentication of the human user (`mcp-user`) in the UI, but the AAuth token chain runs entirely through the Person Server. Make sure it is running before starting any other service.
{: .callout}

---

# Automated Test Harness

The demo ships with a **fully automated test harness** that exercises all three AAuth modes without browser interaction. The harness replaces manual click-through testing with API-level assertions against a running infrastructure.

## Prerequisites

Two services must already be running **before** any test or infrastructure script:

1. **Keycloak** (as shown above — must be running with the `aauth-test` realm configured)
2. **Person Server** (AAuth agent registry):
   ```bash
   cd ~/python/aauth-person-server && ./run-server.sh
   ```
   Verify: `curl http://127.0.0.1:8765/.well-known/aauth-agent.json`

## Infrastructure Scripts

Three scripts manage the lifecycle of all managed services:

| Script | Purpose |
|--------|---------|
| `scripts/start-infra.sh [mode1\|mode3\|user-consent]` | Start agentgateway, aauth-service, and all Python services |
| `scripts/stop-infra.sh` | Kill all managed processes |
| `scripts/run-tests.sh [mode1\|mode3\|user-consent\|all]` | Start infra, run pytest for the mode, stop infra |

### What `start-infra.sh` Does

The script selects the correct config files for the requested mode, then starts each service and waits for it to become healthy:

```bash
./scripts/start-infra.sh mode1

=== Starting AAuth Infrastructure (Mode: mode1) ===
Checking Keycloak...
✓ Keycloak is running
Checking Person Server...
✓ Person Server is already running
Starting agentgateway and aauth-service (Mode: mode1)...
Started agentgateway (PID: 12658)
✓ agentgateway is healthy
Started aauth-service (PID: 12663)
✓ aauth-service is healthy
=== Infrastructure started successfully ===

Running in Mode: mode1
Keycloak:              http://localhost:8080
AgentGateway:          http://localhost:3000
aauth-service:         http://localhost:8081 (HTTP), localhost:7070 (gRPC)
Person Server:         http://127.0.0.1:8765
Backend:               http://localhost:8000
Supply-Chain-Agent:    http://localhost:9999
Market-Analysis-Agent: http://localhost:9998
```

### Port Layout

| Service | Port(s) | Notes |
|---------|---------|-------|
| Keycloak | 8080 | Pre-running, manages `aauth-test` realm |
| Backend | 8000 | FastAPI; receives OIDC-authenticated requests from tests |
| Supply-Chain Agent | 9999 | A2A orchestrator; signs requests, handles AAuth challenges |
| Market-Analysis Agent | 9998 | A2A analyzer; called by supply-chain-agent |
| Agentgateway | 3000 | Proxy + AAuth policy enforcement |
| aauth-service | 7070 / 8081 | ExtAuthz gRPC / HTTP |
| Person Server | 8765 | Agent registry + consent management |

### Mode Configurations

| Mode | agentgateway config | aauth-service config | What it tests |
|------|--------------------|--------------------|---------------|
| `mode1` | `config.yaml` | `aauth-config.yaml` | Identity-only (JWKS signature sufficient) |
| `mode3` | `config-policy.yaml` | `aauth-config-mode3.yaml` | Auth-token required; resource issues 401 challenge |
| `user-consent` | `config-policy.yaml` | `aauth-config-user-consent.yaml` | Auth-token + user consent via Person Server |

## Running the Tests

```bash
# Run all modes end-to-end
./scripts/run-tests.sh all

# Or run a specific mode
./scripts/run-tests.sh mode1
./scripts/run-tests.sh mode3
./scripts/run-tests.sh user-consent
```

The test suite is at `tests/integration/` and uses pytest. Test user credentials are `mcp-user` / `user123` on the `aauth-test` realm — the same user created by `./keycloak/configure-keycloak.sh`. Each test obtains a fresh Keycloak Bearer token via the resource-owner password grant and passes it in the `Authorization` header when calling the backend.

See `TEST.md` in the repo root for the full quick-start guide and troubleshooting tips.

[← Back to index](index.md)
