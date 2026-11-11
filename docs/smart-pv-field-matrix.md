# Smart PV field contract and evidence matrix

This is a **code-verified mapping**, not an authenticated GraphQL introspection result.
The fields below are selected by the checked-in queries on `main` and mapped by the
library's typed models. Their Python types and null handling are shown, **not**
provider-declared GraphQL scalar types or `!` (non-null) schema guarantees.
The existing sanitized fixtures and issue #244's redacted observation support
only the indicated values; synthetic test fixtures are **not provider schema evidence**.

At this audit date (2026-11-11), an authorized provider schema/introspection
result or comprehensive official Smart PV type definition was not available.
Consequently **no additional provider field is independently confirmed**,
and no unverified field is selected in this PR.

## Inventory — `FrankEnergie.smart_pv_systems()`

All paths are relative to `data.smartPvSystems[]`.

| GraphQL field | Python attribute | Python type | Nullable in model | Evidence |
| --- | --- | --- | --- | --- |
| `id` | `SmartPvSystem.id` | `str` | No | Query, model, fixture |
| `brand` | `brand` | `str` | No | Query, model, fixture |
| `connectionEAN` | `connection_ean` | `str` | No | Query, model, fixture |
| `createdAt` | `created_at` | `datetime` | No | Query, model, fixture |
| `deletedAt` | `deleted_at` | `datetime \| None` | Yes | Query, model, null fixture |
| `displayName` | `display_name` | `str \| None` | Yes | Query, model, fixture |
| `externalReference` | `external_reference` | `str` | No | Query, model, fixture |
| `inverterSerialNumbers` | `inverter_serial_numbers` | `list[str]` | Null maps to `[]` | Query, model, fixture and regression |
| `model` | `model` | `str \| None` | Yes | Query, model, fixture |
| `onboardingStatus` | `onboarding_status` | `SmartPvOnboardingStatus` | No | Query, model, fixture |
| `provider` | `provider` | `str` | No | Query, model, fixture |
| `steeringStatus` | `steering_status` | `SmartPvSteeringStatus` | No | Query, model, fixture and redacted observation |
| `updatedAt` | `updated_at` | `datetime` | No | Query, model, fixture |
| `SmartPvSystemPanelGroups` | `panel_groups` | `list[SmartPvSystemPanelGroup]` | No | Query, model, new synthetic fixture |

## Panel groups — `data.smartPvSystems[].SmartPvSystemPanelGroups[]`

| GraphQL field | Python attribute | Python type | Nullable in model | Evidence |
| --- | --- | --- | --- | --- |
| `id` | `SmartPvSystemPanelGroup.id` | `str` | No | Query, model, new synthetic fixture |
| `position` | `position` | `int \| None` | Yes | Query, model, new synthetic fixture |
| `azimuth` | `azimuth` | `int \| None` | Yes | Query, model, new synthetic fixture |
| `tilt` | `tilt` | `int \| None` | Yes | Query, model, new synthetic fixture |
| `capacityKwp` | `capacity_kwp` | `float \| None` | Yes | Query, model, new synthetic fixture |
| `annualKwh` | `annual_kwh` | `int \| None` | Yes | Query, model, new synthetic fixture |
| `panelCount` | `panel_count` | `int \| None` | Yes | Query, model, new synthetic fixture |
| `installationDate` | `installation_date` | `datetime \| None` | Yes | Query, model, new synthetic fixture |

## Summary — `FrankEnergie.smart_pv_system_summary(device_id)`

All paths are relative to `data.smartPvSystemSummary`.

| GraphQL field | Python attribute | Python type | Nullable in model | Evidence |
| --- | --- | --- | --- | --- |
| `operationalStatus` | `SmartPvSystemSummary.operational_status` | `SmartPvOperationalStatus` | No | Query, model, fixture and redacted observation |
| `operationalStatusTimestamp` | `operational_status_timestamp` | `datetime \| None` | Yes | Query, model, fixture |
| `steeringStatus` | `steering_status` | `SmartPvSteeringStatus` | No | Query, model, fixture and redacted observation |
| `totalBonus` | `total_bonus` | `float \| None` | Yes | Query, model, fixture and redacted observation |
| `totalResult` | `total_result` | `float \| None` | Yes | Query, model, expanded synthetic fixture and redacted observation |

These are 14 inventory fields, 8 nested fields, and 5 summary fields
(**27 query-selected fields**). No untyped raw-response passthrough is used.
All selected fields are required to appear in successful responses, even when
the documented Python type accepts an explicit null. Nullability above is
a **library contract** and is not claimed to match the remote schema.

## Verification status and unsupported assumptions

- **Implemented baseline:** all 27 query-selected paths already map to typed
  Python attributes on `main`. This PR expands deterministic tests and
  documents those mappings; it does not add speculative query selections.
- **Verified missing provider fields:** none established by available evidence.
  A new field may only be introduced after an authorized source establishes its
  exact GraphQL type, path, nullability and actual response semantics.
- **Unverified candidates:** additional system metadata, panel-group attributes,
  inverter telemetry, performance/production measurements, unit/currency of
  totals, and other historical/periodic summary fields. These are *categories*
  of investigation, **not confirmed field names or endpoint capabilities**.
- **Status semantics:** `steeringStatus=INACTIVE` does not prove device
  disconnection; `operationalStatus=ON` does not prove actual production.
  `totalBonus` and `totalResult` retain the provider values without
  inferring units or accounting periods.
- **Safety:** a feature-disabled GraphQL error or malformed inventory is not a
  verified empty inventory; see [issue #243](https://github.com/HiDiHo01/python-frank-energie/issues/243).
  No live private records, EANs or serials were used in this audit.

### Follow-up required before closing #244

Obtain authorized, sanitized Smart PV schema/introspection evidence or a
provider-published schema, record exact field definitions and source date,
compare it against this matrix, then add only the newly verified fields
with compatibility-safe models and tests. Without that evidence, **the
completeness claim cannot be established** and this issue stays open.
