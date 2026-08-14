# Repository working agreement

This file applies to the whole repository. Read the nearest scoped `AGENTS.md`
before changing files below it.

## Start here

- Read `dev_doc/README.md` for the documentation map.
- Read `dev_doc/architecture.md` before changing runtime flow or module boundaries.
- Read `dev_doc/development.md` before starting the development container,
  building, flashing, testing, or opening a PR.
- For firmware changes, also read `code/AGENTS.md`.
- For Web UI changes, also read `web/AGENTS.md`.
- For Mock Server changes, also read `mock_server/AGENTS.md`.
- For documentation changes, also read `dev_doc/AGENTS.md`.

## Source of truth

Use this order when facts conflict:

1. Current source and workflow files.
2. Reproducible build or hardware evidence.
3. `dev_doc/`.
4. Root `README.md` and historical discussion.

Do not turn an observed modem response into a general protocol fact without a
captured fixture, hardware report, or another documented promotion path.

## Repository map

- `code/`: the Arduino ESP32-C3 sketch and all runtime code.
- `web/`: the shadcn-svelte source and reproducible LittleFS bundle builder.
- `mock_server/`: the Express implementation of the firmware HTTP contract.
- `scripts/`: stable development entry points for Compose services and builds.
- `dev_doc/`: the only home for development documentation.
- `.github/workflows/`: CI and repository automation.
- `.github/ISSUE_TEMPLATE/`: issue intake forms.
- `assets/`: images used by the public README.

Keep end-user project information in `README.md`. Put development instructions,
architecture, test evidence, and maintenance notes in `dev_doc/`; do not create
new development notes elsewhere.

## Change workflow

- Trace the affected flow and all callers before editing shared behavior.
- Reuse the current Arduino/ESP32 facilities and installed libraries. Add no
  dependency or abstraction without a concrete need.
- Reverse engineering and documentation discovery use deterministic evidence
  checks, not artificial red/green tests.
- Runtime features and bug fixes require a failing check first, then the
  smallest passing change. If host-side automation is impractical, record why
  and use the focused compile/hardware verification in `dev_doc/development.md`.
- Preserve unrelated worktree changes. Stage only intended files.
- Never commit real WiFi, SMTP, webhook, bot, or phone credentials.

## Minimum completion checks

- Run the focused check for the changed area.
- Run the CI-equivalent firmware compile inside the persistent Compose `dev`
  container for runtime changes.
- Run `git diff --check` and inspect tracked, untracked, ignored, staged, and
  latest-commit contents before a PR.
- State clearly which checks were not run, especially hardware checks.
