# Development documentation guide

This file applies to `dev_doc/`. The root `AGENTS.md` also applies.

- Keep all development documentation in this directory and link every document
  from `README.md` here.
- Prefer a task-oriented explanation over a manually maintained per-function
  API catalogue; declarations and source already provide that index.
- Verify claims against current source and workflows. Label hardware-only facts
  with the board/modem and evidence date or report.
- Do not state dependency versions as requirements unless the repository pins
  them. Separate CI baselines from optional hardware-specific settings.
- Write commands from the repository root and make placeholders obvious.
- Update architecture limits, route tables, build commands, and cross-file
  change maps in the same change that alters them.
- Keep credentials and personal machine paths out of examples.
