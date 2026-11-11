# Smart PV inventory and GraphQL status

The asynchronous client exposes the read-only `FrankEnergie.smart_pv_systems()` and
`FrankEnergie.smart_pv_system_summary(device_id)` methods.

The [Smart PV field matrix](smart-pv-field-matrix.md) documents every currently
selected field, its typed model mapping, and the evidence boundary. No provider
schema introspection was available to verify additional fields.

## Inventory: `smart_pv_systems()`

The Smart PV inventory is a `SmartPvSystems` model with a `systems` list.
A verified empty inventory is returned only when the provider successfully
returns an explicitly empty list, without GraphQL errors:

```json
{"data": {"smartPvSystems": []}}
```

A user-supplied, real GraphQL response when **Smart Feed-In is not enabled** is:

```json
{
  "data": null,
  "errors": [
    {
      "message": "user-error:smart-feed-in-not-enabled",
      "path": ["smartPvSystems"]
    }
  ]
}
```

For this exact known response, `smart_pv_systems()` raises
`SmartFeedInNotEnabledException`, a subtype of `RequestException`,
rather than producing a verified empty inventory. The exception does
**not** establish whether physical solar panels exist, or whether
previously registered hardware was disconnected.

Missing, partial, malformed or error-bearing inventories raise
`RequestException` rather than being silently treated as absent.
Returned systems require complete queried records and unique nonblank
string IDs. Nested panel groups also require valid unique IDs.
Malformed non-null panel-group numeric values and dates are rejected rather
than silently interpreted as missing. Valid null optional values and
supported numeric-string representations remain accepted.
A null or non-string `connectionEAN` is invalid; `deletedAt`
may be null but must be a valid date string when present.
A `null` inverter-serial-number list retains its supported
empty-list model representation.

## Summary: `smart_pv_system_summary(device_id)`

A summary independently contains `operational_status`,
`operational_status_timestamp`, `steering_status`,
`total_bonus` and `total_result`. A provider-reported
`operational_status=ON` is not a production measurement;
`steering_status=INACTIVE` does not establish disconnection.
UTC timestamps remain timezone-aware.

## Downstream applications

A consumer must distinguish a successful empty PV inventory from
`SmartFeedInNotEnabledException` and other `RequestException`
results. In particular, Home Assistant's stale-device Repairs
must not count feature-disabled or malformed responses as
verified absence.

Related: [python-frank-energie #243](https://github.com/HiDiHo01/python-frank-energie/issues/243)
and [Home Assistant #455](https://github.com/HiDiHo01/home-assistant-frank_energie/issues/455).
