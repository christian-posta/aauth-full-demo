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
curl -LO https://github.com/christian-posta/keycloak-aauth-extension/releases/download/v1.0.0/keycloak-aauth-extension-1.0.0.jar

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

Test whether the aauth/auth and token endpoints are available:

```bash
curl http://localhost:8080/realms/aauth-test/protocol/aauth/agent/auth

{"error":"invalid_request","error_description":"Missing required parameter: request_token"}%
```

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
- enforce allow/deny policy based on agent identity (jwks, jwt, etc)
- enforce rate limit policy based on authentication levels

To get started with Agentgateway for this AAuth demo, you can [download the release](https://github.com/christian-posta/agentgateway/releases/tag/v0.11.3) and configure it with the config.yaml in this source code repo.

```bash
# Download Agentgateway binary (for macOS amd64) and rename to 'agentgateway'
curl -L -o agentgateway https://github.com/christian-posta/agentgateway/releases/download/v0.11.3/agentgateway-darwin-amd64
chmod +x agentgateway
```

Now you can run agentgateway with configurations for this demo:

```bash
./agentgateway -f ./agentgateway/config.yaml
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


At this point we can proceed with the demo. 

