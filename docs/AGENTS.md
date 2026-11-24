# AGENTS.md

These instructions apply to `docs/` and its descendants. Read the repository [AGENTS.md](https://github.com/HiDiHo01/python-frank-energie/blob/main/AGENTS.md), [AI_POLICY.md](https://github.com/HiDiHo01/python-frank-energie/blob/main/AI_POLICY.md) and the local [AI_POLICY.md](https://github.com/HiDiHo01/python-frank-energie/blob/main/docs/AI_POLICY.md) before working here. The root requirements remain mandatory; report conflicts and do not weaken them.

## Documentation

- Treat this directory as the canonical public documentation source. Keep API examples aligned with current source, tests and supported Python versions.
- Separate observed behavior from proposed behavior. Record provider, observation date and evidence limitations for new API fields or enum values. Do not imply schema completeness or infer one status from another.
- Keep examples free of credentials, account identifiers and private telemetry. Use synthetic examples or explicitly sanitized observations.
- Preserve the configured GitHub Pages subpath and navigation in `zensical.toml`. Use repository URLs for source references outside the documentation directory.
- Do not add contributor instruction files to the public navigation. Check rendered links and the documentation build using the existing workflow; do not deploy from a pull request.
