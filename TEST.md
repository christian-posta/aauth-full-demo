Okay right now here's how I run this project:

1. Start Keycloak. If it's already running, should be good.

It needs to be run from this folder:

```shell
~/temp/keycloak-aauth/keycloak-26.2.5 
```

And the command to run it is:

```shell
./bin/kc.sh start-dev --bootstrap-admin-username=admin --bootstrap-admin-password=admin 
```

Like I said if it's already running from this path on port 8080 we are in good shape. 

The user I use to login to the app through keycloak (app redirects) is "mcp-user" with password user123. We have a script that approximately configures this here:

```shell
./keyloak/configure-keycloak.sh
```

But I don't think I've run that in a long time. I have Keycloak configured and just run it from that dir.

2. Run Agentgateway

The binary lives on the machine 'agentgateway' so we start it with 

```shell
cd agentgateway
agentgateway -f config.yaml
```


This starts things in "Mode 1" demo where we just test out the identity. You can check the config.yaml to see the authorization rules. Note, we call out to an ext-auth service. Once we start agent gateway we have to start that too:

from 'agentgateway' dir:

```shell
./run-aauth-extauth.sh
```

This will start the extauth server. The actual binary lives here:

```shell
~/go/src/github.com/christian-posta/extauth-aauth-resource
```

that's for mode 1. For mode 3, we need to restart agentgateway with config-policy.yaml and the extauth server like this:

```shell
AAUTH_CONFIG=aauth-config-mode3.yaml ./run-aauth-extauth.sh
```

For the "user consent flow" where I have to consent to a specific scope after invoking the agent, it's like this:

```shell
AAUTH_CONFIG=aauth-config-user-consent.yaml ./run-aauth-extauth.sh
```

3. Okay last infra piece we need to start the person server (PS):

```shell
cd ~/python/aauth-person-server
./run-server.sh
```

4. Now we run the components from this dir:

- supply-chain-ui:

npm start

- backend:

uv run .

- supply-chain-agent

uv run .

- market-analysis-agent

uv run .


On startup, each backend/supply-chain-agent/market-analysis-agent try to bootstrap an aa-agent+jwt token from the PS / agent server.

You can take a look at how that all works in the src here and the person server code base ('~/python/aauth-person-server`)

On a fresh start of PS (which is not normal, i usually have it ready to go), it will need consent/approval for teh agents coming online before giving the agent token. I think there is a rest API to do that.