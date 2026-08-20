# Development documentation guide

This file applies to `dev_doc/`. The root `AGENTS.md` also applies.

- Keep development documentation in this directory. Link each document from
  `dev_doc/README.md`.
- Use task-oriented instructions. Do not maintain a manual per-function API
  catalog when declarations and OpenAPI already provide that information.
- Validate claims against the current source, workflow files, and
  `openapi.json`.
- Label hardware facts with the board, modem, input, and observed result.
- Write commands from the repository root. Use clear placeholders for local
  paths, ports, credentials, and keys.
- Update architecture limits, route groups, build commands, and the document
  map in the same change that alters them.
- Classify documentation languages in `document-languages.json`. A Simplified
  Chinese document must have both Traditional Chinese and English equivalents.
- Do not add credentials, personal machine paths, raw SMS content, or complete
  device identifiers to examples.
