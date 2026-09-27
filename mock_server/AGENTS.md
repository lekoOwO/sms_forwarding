# Mock Server change guide

This file applies to `mock_server/`. The root `AGENTS.md` also applies.

- Treat `components/idf_web/`, `components/idf_config/`, and their current callers as the behavior source.
- Keep the route and schema contract in `dev_doc/openapi.json`.
- Serve `web/build/index.html`. Do not create a second Mock-only UI.
- Keep state in memory unless a test requires persistence across restarts.
- Use Node built-ins and Express before adding a dependency.
- Run `npm test` after changes.
