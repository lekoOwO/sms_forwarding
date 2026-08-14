# Web UI change guide

This file applies to `web/`. The root `AGENTS.md` also applies.

## Boundaries

- `src/routes/+page.svelte` owns the single device administration page.
- `src/lib/locales/` owns all visible copy in Traditional Chinese, Simplified
  Chinese, and English. Keep all three files on the same key set.
- `src/lib/api.ts` owns calls to the authenticated firmware routes. Never render
  device responses as raw HTML.
- `scripts/package.mjs` creates the bounded gzip file consumed by firmware.
- Generated output lives in `web/build/` and `code/data/index.html.gz`; do not
  hand-edit either artifact.

Use existing shadcn-svelte components and semantic theme tokens. Keep the page
fully static, dependency-free at runtime, keyboard usable, and functional on a
narrow mobile viewport. Do not add a router, state library, or i18n package for
this single page.

Prefer flat sections composed with Navigation Menu, Accordion, Field, Input
Group, Tabs, and Badge. Use definition lists for small device summaries and
reserve Table for genuinely tabular comparisons. Do not add Card unless the
content is an independent object that needs its own container.

## Verification

Run in the persistent container:

```sh
docker compose exec dev sh -lc 'cd web && npm run check && npm run filesystem'
python3 -m unittest tests/test_web_bundle.py
```

Then run the firmware compile from `../dev_doc/development.md`.
