# Additional read-only GraphQL operations

The following five selections were previously stored as commented GraphQL
examples in `python_frank_energie/frank_energie.py`. They now have typed
asynchronous methods on `FrankEnergie`. All use the existing authenticated
transport and accept no operation-specific arguments.

| Method | operationName | Root selection | Return type |
| --- | --- | --- | --- |
| `user_smart_charging()` | `UserSmartCharging` | `userSmartCharging` | `dict[str, object] \| None` |
| `app_version()` | `AppVersion` | `appVersion` | `dict[str, object] \| None` |
| `user_rewards_data()` | `UserRewardsData` | `me`, `userRewardsData` | `dict[str, dict[str, object] \| None]` |
| `tree_certificates()` | `TreeCertificates` | `treeCertificates` | `list[dict[str, object]] \| None` |
| `app_notice()` | `AppNotice` | `appNotice` | `dict[str, object] \| None` |

## Provider verification status

- **UserSmartCharging:** two sanitized read-only live responses on
  2026-11-11 confirmed both `isActivated: false` (with
  `userCreatedAt: null` and `userId: null`) and `isActivated: true`
  (with an ISO 8601 UTC `userCreatedAt` timestamp string and a nonempty
  opaque `userId`). Both returned `provider: "ENODE"`,
  `isAvailableInCountry: true`, `needsSubscription: false`,
  and `subscription: null`. This verifies the field selection and absence
  of operation arguments for the observed accounts, not universal availability
  or a non-null subscription shape. Tests use a synthetic user ID and timestamp;
  originals are not stored in this repository.
- **AppVersion:** a read-only live response on 2026-11-11 returned
  `{"data": {"appVersion": {"ios": null, "android": null}}}`. This confirms
  the named operation, the root object, and the platform fields for the
  observed account. Both platform objects can be null; null must not be
  interpreted as a validation error or invented version data.
- **UserRewardsData:** two read-only live responses on 2026-11-11 confirmed
  both root objects: `me` with `id` and `UserSettings` (`id` and
  `rewardPayoutPreference: "DISCOUNT"`), and `userRewardsData`.
  The first had `activeConnectionsCount: 1`, `activeFriendsCount: 0`,
  `acceptedRewards: []`, and `upcomingRewards: []`. The second had
  `activeConnectionsCount: 1`, `activeFriendsCount: 1`, one populated
  `acceptedRewards` record and `upcomingRewards: []`. The populated
  reward included numeric awards and connection values, nullable
  `awardedTreesAmount: null`, UTC timestamp strings
  (`availableForAcceptanceOn`, `acceptedOn`), boolean flags
  (`isRewardForOwnSignup`, `hasPossibleSmartChargingBonus`),
  `coolingDownPeriod`, nested `InviteLink`, and
  `AdditionalBonuses: []`. The observed `InviteLink` included
  `id`, `type: "GROUP"`, `fromName`, `templateType: "DEFAULT"`,
  `awardRewardType`, `treesAmountPerConnection`, and
  `discountPerConnection`. Account, invitation and reward IDs,
  referrer names, and original dates are not stored in the repository;
  tests use entirely synthetic values. Nonempty `upcomingRewards`
  and `AdditionalBonuses` have not yet been observed.
- **TreeCertificates:** a read-only live response on 2026-11-11
  returned `{"data": {"treeCertificates": []}}`. This confirms the named
  operation and explicitly empty inventory for the observed account. It
  does not verify the shape of populated certificate records.
- **AppNotice:** a read-only live response on 2026-11-11 confirmed
  `appNotice` as an object with `active: true`, a non-empty `message`,
  and `title: ""` (an explicitly empty string). The actual notice message
  is not recorded in this repository; tests use synthetic text. This confirms
  the observed named operation and selection for one account, not every
  possible future notice state.

## Data and error semantics

A successful response must include `data` as an object and the selected root
fields. **An explicitly returned `null` is retained as `None`**; a missing
root, malformed record, or malformed `errors` container raises
`RequestException`. Only `treeCertificates: []` confirms a successful empty
certificate list. Selected fields must be present, including nullable ones. A non-null
Smart Charging subscription must contain `startDate`, `endDate`, `id`, and
`proposition`; its proposition must contain `product` and `countryCode`.
A null subscription stays valid. Non-null subscription responses have not been
observed from the provider, so these shape checks use synthetic fixtures.
For non-null app-version platforms, `version` must be present and be a string or null.
For non-null reward data, `acceptedRewards` and `upcomingRewards` must be
lists; each reward and its non-null selected nested records must have the
selected keys. `me.UserSettings` must have its selected keys when non-null.
No values are invented or coerced, and the methods do not log raw responses,
user IDs, reward details, or tokens. Malformed JSON envelopes and error
containers are rejected before the shared GraphQL error handler; provider
error details for these operations are suppressed while known authentication,
timeout and rate-limit classifications remain intact.

`user_rewards_data()` returns both root fields so `me: null` is not confused
with `userRewardsData: null`. Rate limits, auth errors, request/network errors
and `asyncio.CancelledError` propagate through the normal transport contract.

## Example

```python
async with FrankEnergie() as client:
    await client.login(username, password)
    status = await client.user_smart_charging()
    certificates = await client.tree_certificates()
```

Provide `username` and `password` securely at runtime; never commit them or
write returned account data into logs. Add live provider fixtures only after
they have been sanitized. Routine regression tests use synthetic values.
