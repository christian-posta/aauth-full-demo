# Documentation

Jekyll documentation site using the [Just the Docs](https://just-the-docs.com) theme, loaded via `remote_theme: just-the-docs/just-the-docs@v0.12.0`. GitHub Pages resolves the theme at build time (the `jekyll-remote-theme` plugin is enabled in [`_config.yml`](_config.yml)).

## Running locally

From the `docs/` directory (requires Ruby and Bundler):

```bash
bundle install
bundle exec jekyll serve --livereload
```

Then open http://localhost:4000/aauth-full-demo/

On first `bundle install`, gems are downloaded; the remote theme is fetched during `jekyll serve` / `jekyll build`.
