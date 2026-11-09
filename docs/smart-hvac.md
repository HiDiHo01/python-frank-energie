# Smart HVAC API

The Frank Energie client supports the site-level Smart HVAC feature status
separately from device inventory and device telemetry.

The observed API contract comes from a sanitized capture of Frank app 4.35.0.
These endpoints have **not** been tested for every country, account or device.
Do not treat feature activation or the provider's `ACTIVE` status as proof that
a heat pump is currently heating, cooling or being actively steered.

## Site-level feature status

```python
# api: authenticated FrankEnergie instance
feature = await api.smart_hvac_status(site_reference)
if feature is not None:
    activated = feature.isActivated
    available_on_site = feature.is_available_on_site
```

`smart_hvac_status(site_reference: str)` calls the root-level
`userSmartHvac(siteReference: String!)` query, **not** the invalid
`me { smartHvac { ... } }` query.

**Breaking caller change:** `site_reference` is mandatory. Previously the
method took no argument; downstream callers, including Home Assistant's
`_fetch_user_data()`, must pass the currently selected site reference.
The library does not infer a site for multi-site accounts.

The `SmartHvac` model preserves `True`, `False` and `None` independently for
`isActivated`, `isAvailableInCountry`, `is_available_on_site` and
`has_accepted_terms` (the corresponding GraphQL fields use camelCase). Missing or null flags mean unknown, not `False`.
Unexpected types raise `RequestException`. An explicit null
`userSmartHvac` field returns `None`; a missing/malformed GraphQL response
raises an exception rather than reporting the feature as disabled.

The pre-existing `me(site_reference)` method also includes the
`userSmartHvac` root field in the merged [PR #226](https://github.com/HiDiHo01/python-frank-energie/pull/226).
That is optional on its model. Callers that only need feature state can use the
dedicated query and avoid requesting all personal account data.

## Device-oriented API

These methods are independent operations. They are intentionally **not**
implicitly called by `smart_hvac_status()` or `me()`:

| Client method | GraphQL root field | Result |
| --- | --- | --- |
| `smart_hvacs(site_reference)` | `smartHvacs(siteReference:)` | `list[SmartHvacDevice]` |
| `smart_hvac(device_id)` | `smartHvac(deviceId:)` | `SmartHvacDevice \| None` |
| `smart_hvac_summary(device_id)` | `smartHvacSummary(deviceId:)` | `SmartHvacSummary \| None` |
| `smart_hvac_connect_requests()` | `smartHvacConnectRequests` | `list[SmartHvacConnectRequest]` |

The device inventory and detail include only the captured fields: brand,
connection EAN, creation/deletion timestamps, device type, display name,
reauthentication requirement, external reference, ID, model, provider and update
timestamp. Timestamp fields are normalized to timezone-aware UTC datetimes.
Identifiers are returned to authorized callers, never logged.

The summary returns session dates, raw `operational_status`,
`operational_status_timestamp`, raw `steering_status` and `total_result`.
Only `ACTIVE` has been observed for the two status fields: the model keeps
unknown values as strings without inventing an enum or runtime mapping.
The connect-request operation returns brand, error, ID and opaque status text.

Only an explicitly empty list (`[]`) is an empty device inventory or empty
connect-request list. Missing, null, malformed or partially invalid list
responses raise `RequestException`. Duplicate device IDs are rejected.
An explicitly null single device/summary response returns `None`.

## Error and privacy guarantees

- Missing authentication raises `AuthRequiredException`.
- Missing/blank site or device identifiers raise `ValueError`.
- Upstream authentication and rate-limit exceptions propagate unchanged.
- Malformed GraphQL responses, unsupported queries, and unrecognized API errors
  are **not** quietly mapped to empty collections or `False` flags.
- New Smart HVAC operations use redacted diagnostics; responses, account IDs,
  device IDs, EANs and external references must not appear in exception text
  or logs.
- No periodic polling is introduced. A downstream application chooses when to
  call device endpoints and must isolate feature errors from unrelated entities.
  In Home Assistant, the separate integration issue
  [#414](https://github.com/HiDiHo01/home-assistant-frank_energie/issues/414)
  covers sensor semantics, availability and translations.

The observed payloads used for tests are synthetic or sanitized. Additional
upstream response variants should be added only when independently verified.
