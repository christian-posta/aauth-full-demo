# Documentation

More to come here!

## Running locally

From the `docs/` directory, run Jekyll with Docker:

```bash
docker run --rm -p 4000:4000 -v "$(pwd)":/srv/jekyll -w /srv/jekyll \
  mcr.microsoft.com/devcontainers/jekyll:bookworm \
  sh -c "bundle install && bundle exec jekyll serve --livereload --host 0.0.0.0"
```

Then open http://localhost:4000/aauth-full-demo/
