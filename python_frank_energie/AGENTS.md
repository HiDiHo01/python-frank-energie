# AGENTS.md

These instructions apply to `python_frank_energie/` and its descendants. Read the repository [AGENTS.md](../AGENTS.md), [AI_POLICY.md](../AI_POLICY.md) and the local [AI_POLICY.md](AI_POLICY.md) before working here. The root requirements remain mandatory; report conflicts and do not weaken them.

## SDK implementation

- Trace changes from public exports in `__init__.py` through the client, transport and model boundaries. Preserve public signatures, aliases, model defaults, exception contracts and caller-owned sessions.
- Keep GraphQL selections grounded in verified provider evidence. Distinguish observed values, inferred semantics and unverified providers; never use introspection.
- Preserve missing, null, empty, invalid and genuine zero values according to the operation contract. Do not infer battery activity, steering, connection or congestion from another status.
- Keep unknown-status diagnostics privacy-safe and bounded. Do not pass arbitrary provider strings to enum loggers.
- Add deterministic regression tests for affected parsing, outgoing selections, exception paths and cancellation as applicable. Run the root Python quality checks and update the architecture reference for changed contracts.
