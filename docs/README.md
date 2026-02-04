# Documentation

- **[USER_DELEGATED_AAUTH.md](USER_DELEGATED_AAUTH.md)** — User-delegated AAuth flow: consent, auth tokens (`scheme=jwt`), resource tokens, and multi-hop token exchange (Backend → Supply Chain Agent → Market Analysis Agent). Describes components, behavior, and sequence.

- **[AAUTH_CONFIGURATION.md](AAUTH_CONFIGURATION.md)** — Configuration reference: environment variables for Backend, Supply Chain Agent, Market Analysis Agent, and Frontend; Keycloak setup; hostnames and ports.

See also the root [README.md](../README.md), [SPEC.md](../SPEC.md), and each component’s README (`backend/README.md`, `supply-chain-agent/README.md`, `market-analysis-agent/README.md`).

## Running locally

From the `docs/` directory, run Jekyll with Docker:

```bash
docker run --rm -p 4000:4000 -v "$(pwd)":/srv/jekyll -w /srv/jekyll \
  mcr.microsoft.com/devcontainers/jekyll:bookworm \
  sh -c "bundle install && bundle exec jekyll serve --livereload --host 0.0.0.0"
```

Then open http://localhost:4000/aauth-full-demo/
