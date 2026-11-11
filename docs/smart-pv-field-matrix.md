# Smart PV field contract and evidence matrix

This is a **code-verified mapping**, not an authenticated GraphQL introspection result.
The fields below are selected by the checked-in queries on `main` and mapped by the
library's typed models. Their Python types and null handling are shown, **not**
provider-declared GraphQL scalar types or `!` (non-null) schema guarantees.
The existing sanitized fixtures and issue #244's redacted observation support
only the indicated values; synthetic test fixtures are **not provider schema evidence**.

On 2026-11-11, authorized read-only diagnostics reported that `__typename`
succeeded but `__schema` returned `GRAPHQL_VALIDATION_ERROR`. This does not
prove why introspection was rejected. No provider SDL or comprehensive official
Smart PV type definition was available. **No additional provider field was
independently confirmed**; merged PR #246 did not select speculative fields.
The scope of [issue #244](https://github.com/HiDiHo01/python-frank-energie/issues/244)
is limited to independently verifiable, relevant fields, **not** an exhaustive
inventory of the external provider schema.

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
  Python attributes on `main`. Merged PR #246 expanded deterministic tests
  and documented those mappings; no speculative query selections were added.
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

### Acceptance boundary for issue #244

Completion means that **all independently verifiable, relevant Smart PV fields
within the supported read-only operations** have documented evidence, are
selected in the corresponding GraphQL queries, and are exposed through typed
models with compatible behavior and regression tests. This matrix separates:

- **Already implemented:** the 27 selected paths listed above.
- **Independently confirmed but missing:** none identified from available evidence.
- **Unverified candidates:** the categories listed above; their existence,
  schema types, nullability, units and response semantics remain unconfirmed.

A provider SDL or successful `__schema` introspection is **not a prerequisite**
for closing #244 under its revised criteria, provided the bounded mapping,
quality checks and mandatory human review have been verified. Closing the issue
must **not** be described as proof that all fields supported by the provider
have been discovered.

If additional fields are independently confirmed later, document their exact
source, GraphQL path, types and semantics, and track any required model/query
changes as separate follow-up work. Do not guess unsupported field names.
