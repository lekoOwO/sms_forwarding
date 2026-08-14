# Mock Server change guide

This file applies to `mock_server/`. The root `AGENTS.md` also applies.

- Treat `code/code.ino` and `code/web_handlers.cpp` as the behavior source.
- Keep the route and schema contract in `dev_doc/openapi.json`.
- Serve `web/build/index.html`. Do not create a second Mock-only UI.
- Keep state in memory unless a test requires persistence across restarts.
- Use Node built-ins and Express before adding a dependency.
- Run `docker compose exec -T mock-server npm test` after changes.
