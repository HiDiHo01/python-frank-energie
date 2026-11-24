# AGENTS.md

These instructions apply to `scripts/` and its descendants. Read the repository [AGENTS.md](../AGENTS.md), [AI_POLICY.md](../AI_POLICY.md) and the local [AI_POLICY.md](AI_POLICY.md) before working here. The root requirements remain mandatory; report conflicts and do not weaken them.

## Diagnostic and maintenance scripts

- Inspect the existing script and checked-in API operations before adding a diagnostic. Standalone diagnostics must not import the SDK when their purpose is to verify raw provider data independently.
- Reuse local credential configuration where applicable, including the existing `.env` convention. Never create or overwrite credentials automatically, print secrets, or include them in artifacts.
- Default diagnostics to read-only data operations after authentication. Never send introspection queries or speculative fields. Mutating maintenance scripts must make their intended effects explicit and require appropriate authorization.
- Use TLS verification, bounded request sizes and timeouts, bounded request counts, and no speculative retries. Follow the root async requirements; isolate blocking standard-library calls from an event loop.
- Preserve raw null, missing, empty and zero distinctions while redacting identifiers, arbitrary upstream text and error payloads. Separate provider observations from SDK interpretation.
- Validate with synthetic responses, including authentication failure, invalid data and rate limiting. Live tests require separate authorization and must report only sanitized evidence.
