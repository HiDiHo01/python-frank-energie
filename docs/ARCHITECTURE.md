# Architecture and public API compatibility

This reference records the behavior of `python-frank-energie` after the
[`user_sites()` alias in PR #240](https://github.com/HiDiHo01/python-frank-energie/pull/240).
The [refactoring sequence](#proposed-refactoring-sequence) describes future work
tracked in [issue #177](https://github.com/HiDiHo01/python-frank-energie/issues/177).

## Current implementation

### Components and responsibilities

| Component | Responsibility and dependencies |
| --- | --- |
| [`FrankEnergie`](../python_frank_energie/frank_energie.py) | The async client façade defines GraphQL operations, validates method arguments, manages authentication and HTTP state, sends requests, and passes responses to model parsers. Public methods can apply operation-specific error handling after the shared transport. |
| `FrankEnergieQuery` in [`frank_energie.py`](../python_frank_energie/frank_energie.py) | Holds the GraphQL document, operation name, and variables. The constructor accepts a `dict` or `None` for variables and raises `TypeError` for other values. `to_dict()` returns a `dict[str, Any]` with `query`, `operationName`, and `variables`. A supplied variables dictionary is shared with the returned payload. |
| `Authentication` in [`models.py`](../python_frank_energie/models.py) | Represents the client's current credentials and expiry metadata. The client constructs it from supplied tokens or parses the result of a login or renewal mutation. The separate [`authentication.py`](../python_frank_energie/authentication.py) model is the package export. |
| GraphQL transport and errors in [`frank_energie.py`](../python_frank_energie/frank_energie.py) | Private client helpers prepare headers, post JSON through `aiohttp`, classify HTTP and GraphQL errors, and return the response for parsing. The exception types live in [`exceptions.py`](../python_frank_energie/exceptions.py). |
| [`models.py`](../python_frank_energie/models.py) and [`domain.py`](../python_frank_energie/domain.py) | Model parsers translate response fields to Python objects. The module includes dataclasses, a Pydantic `DeliverySite`, domain-specific validation, legacy accessors, and price and battery calculations. `domain.py` provides enums used by the models, including status enums with an `UNKNOWN` fallback. [`time_periods.py`](../python_frank_energie/time_periods.py) supplies price-period helpers. |
| [`weighted_average_prices.py`](../python_frank_energie/weighted_average_prices.py) | Provides isolated, typed GraphQL response models and validation for the additive weighted-average-price operation. Values and timestamps are not recalculated; malformed or missing selected data raises `RequestException`. |
| HTTP session and token renewal in [`frank_energie.py`](../python_frank_energie/frank_energie.py) | The client borrows an injected `aiohttp.ClientSession` or lazily creates one. `_prepare_query_headers()` and `validate_authentication()` coordinate expiry-driven renewal with a per-client lock. `renew_token()` sends the renewal mutation through the same transport. |

### Runtime state and ownership

The following state is initialized by `FrankEnergie.__init__()`.

| State | Lifecycle and source of truth |
| --- | --- |
| `self._auth` | The authoritative credential object for this client. It starts as `None` unless either constructor token is truthy, in which case the missing token is represented by an empty string. Successful `login()` and `renew_token()` replace it. A rejected refresh token (`RefreshTokenInvalidException` raised by the renewal request) or a successful `logout()` clears it. Rate-limited renewal leaves it intact. Header construction, renewal variables, and the client expiry properties read from it. |
| `self.access_token`, `self.refresh_token` | Publicly named, writable placeholders initialized to `None`. The package has no other reads or writes of these attributes. The constructor arguments `auth_token` and `refresh_token` populate `_auth`. Any external reliance on the placeholders' presence or writability still needs to be checked. |
| `self._site_reference` | Initialization-only field set to `None`. Site discovery returns site data to the caller. Site-scoped requests use the explicit `site_reference` argument, so the caller's selection is authoritative. `UserSites()` has an optional argument for compatibility and sends no site filter. |
| `self._resolution` | Initialization-only field set to `"PT60M"`. Public market-price requests use their `resolution` argument, which defaults to `"PT15M"`. `user_prices()` retains a `resolution` parameter but omits it from the GraphQL variables. The contract-resolution methods use an explicit connection ID and parse the API's state or change result. `_resolution` has no role in either flow. |
| `self._session` | The active HTTP session reference, initially the injected session or `None`. `_ensure_session()` creates a session only when the reference is `None` and marks it as client-owned through `_close_session`. `close()` closes and clears a client-owned session and leaves an injected session open for its owner. A later request can create a new internal session. |
| `self._renew_lock` | An `asyncio.Lock` created per client. Header preparation rechecks expiry after acquiring it. `validate_authentication()` also checks expiry under this lock. Direct calls to `renew_token()` bypass the lock. The lock coordinates these automatic checks within one client instance. |

`_user_country` is also initialization-only. Price and site context come from
the arguments and returned models. `_last_query` and `_last_variables` retain
the last request and its variables until a later `_query()` replaces them or
the client instance is discarded. After `login()`, these references can retain
the login password; `close()` does not clear them. The transport logs variable
names, not values, but retained request state must not be shared in diagnostics
or logs. `get_diagnostic_data()` currently returns a fixed string. The client
holds credentials in memory.

### Request lifecycle and error handling

1. A public operation builds `FrankEnergieQuery`. The shared `_query()` checks
   that the query has a callable `to_dict()` and a nonempty operation name.
2. Header preparation renews the token when `_auth.is_expired` applies. It
   adds the current bearer token when `_auth` is present. `RenewToken` skips
   both the expiry precheck and automatic bearer header. See the
   [authentication guide](authentication.md#current-authentication-lifecycle).
3. The transport posts JSON to `FrankEnergie.DATA_URL` with an `aiohttp`
   `ClientTimeout(total=30)`. It checks HTTP status before decoding JSON.
   The transport propagates cancellation. Rate limiting supplies a retry hint
   for caller scheduling without sleeping or replaying the request.
4. The client classifies GraphQL errors and then delegates response parsing to
   the operation's model. Recognized errors retain their response order.
   `me()` can keep usable account data if all errors belong to the optional
   `userSmartHvac` field and no recognized failure takes precedence.
   `month_summary()` handles the known missing-meter-reading response as
   `None`. Smart HVAC query operations enforce stricter response validation
   and redact relevant errors at transport and parsing boundaries. This does
   not cover every Smart HVAC mutation: `smart_hvac_update_settings()` can log
   device identifiers and raw failed responses. Such mutation logs are not
   guaranteed sanitized and require review before sharing.

The following mappings apply at the shared request boundary. Individual public
wrappers can preserve, translate, or handle these errors as described below.

| Failure | Shared request result |
| --- | --- |
| HTTP 401, 403, 400 | `AuthRequiredException`, `AuthException`, `RequestException`, respectively. |
| HTTP 500 and other unmapped HTTP response errors, including `ContentTypeError` for a successful non-JSON response | `FrankEnergieException`. |
| Client timeout, non-response `aiohttp.ClientError` (excluding `ClientResponseError`), or the recognized GraphQL backend timeout | `NetworkError`. |
| HTTP 429 or the recognized GraphQL `Too Many Requests` message | `RateLimitException` (a `RequestException`) with `operation_name` and optional `retry_after` seconds. See [rate-limit errors](rate-limits.md). |
| Known GraphQL authentication or feature errors | Typed exceptions such as `AuthException`, `AuthRequiredException`, `RefreshTokenInvalidException`, `SmartTradingNotEnabledException`, `SmartChargingNotEnabledException`, and `SmartBatteryNotFoundException`. `RefreshTokenInvalidException` subclasses `AuthException`. |
| Other GraphQL errors or malformed responses | Handling depends on the operation. Some errors reach the model parser, which may raise `RequestException` or apply a model-specific fallback. The dedicated [Smart HVAC operations](smart-hvac.md#error-and-privacy-guarantees) reject malformed responses. |

See the request-boundary tests for [timeouts and cancellation](../tests/test_graphql_timeouts.py),
[rate limits](../tests/test_rate_limits.py), and [partial account responses](../tests/test_me_partial_errors.py).

### Public compatibility surface

#### Import paths

| Import path | Current surface |
| --- | --- |
| [`python_frank_energie`](../python_frank_energie/__init__.py) | `FrankEnergie`, `Authentication`, `CountryCode`, `EnergyType`, `Resolution`, `ContractPriceResolutionChangeResult`, `ContractPriceResolutionState`, `Invoices`, `MarketPrices`, `PeriodUsageAndCosts`, `WeightedAveragePrices`, `WeightedAveragePriceCategory`, `WeightedAveragePriceItem`, `Price`, `PriceData`, `SmartHvac`, `SmartHvacConnectRequest`, `SmartHvacDevice`, `SmartHvacSummary`, `AuthException`, `ConnectionException`, `RateLimitException`, and `RequestException` are in `__all__`. The module also exposes `__version__`. |
| [`python_frank_energie.frank_energie`](../python_frank_energie/frank_energie.py) | The same `FrankEnergie` class and the directly importable `FrankEnergieQuery` and `sanitize_query()`. The latter masks a password through the shared variables dictionary. `_query()` is private. |
| [`python_frank_energie.authentication`](../python_frank_energie/authentication.py) | The package-exported `Authentication` class and the separate `AuthenticationResult` dataclass with `authToken` and `refreshToken` fields. |
| [`python_frank_energie.models`](../python_frank_energie/models.py) | The operation result models, including `UserSites`, `DeliverySite`, `Me`, `User`, and the distinct runtime `Authentication` class. Models such as `PriceData` re-exported by the package root refer to the same classes as their definitions here. |
| [`python_frank_energie.exceptions`](../python_frank_energie/exceptions.py) | The root-exported exceptions and additional types such as `FrankEnergieException`, `AuthRequiredException`, `RefreshTokenInvalidException`, `NetworkError`, and `NoMarketPricesAvailableException`. `ConnectionException` and `NetworkError` are distinct classes. |
| [`python_frank_energie.domain`](../python_frank_energie/domain.py) and [`python_frank_energie.types`](../python_frank_energie/types.py) | `CountryCode`, `EnergyType`, and the root-exported `Resolution` are domain enums. `models.Resolution` is a separate enum used by the contract-resolution mutation with the same two values, `PT15M` and `PT60M`. `types.PriceResolution` and `types.CountryCode` are literal type aliases. |

#### Client lifecycle and properties

- `FrankEnergie(clientsession=None, auth_token=None, refresh_token=None, version=None)`
  constructs the client synchronously. `async with` returns the same client and
  calls `await close()` on exit without suppressing exceptions. `close()`
  returns `None` and follows the [session ownership rules](#runtime-state-and-ownership).
- `is_authenticated` is a `bool` property that checks for a nonempty access
  token in `_auth`. `validate_authentication()` is async and returns `bool`.
  It checks credential presence under the per-client renewal lock, renews
  when needed, and rechecks local state before returning. Absent authentication
  or caught `AuthException`/`AuthRequiredException` produces `False`. Request
  failures such as `RateLimitException` and `NetworkError` can propagate.
- `auth` is a deprecated property that logs a message and returns the current
  `models.Authentication | None`. `token_expires_at` and
  `refresh_token_expires_at` are read-only `datetime | None` properties.
- `login(username, password)` is annotated `models.Authentication | None`.
  Success returns the installed runtime object. Missing credentials raise
  `ValueError`, authentication failures raise `AuthException`, and
  `NetworkError` and `RateLimitException` are propagated.
  `renew_token()` returns the new `models.Authentication`. It raises
  `AuthRequiredException` when `_auth` is absent and propagates renewal errors,
  including `RefreshTokenInvalidException` and `RateLimitException`.
- `logout(installation_id)` returns `bool` and raises `AuthRequiredException`
  when the local authentication check fails. It returns `False` for caught
  request failures or an unsuccessful response. Success clears `_auth`.
- `generate_system_user_agent()` (static) and `get_diagnostic_data()` are
  synchronous and return `str`.

#### Operation methods and return types

All operations in this table are async. Most result models come from `models.py`; the weighted-average-price models come from `weighted_average_prices.py`.

| Area | Method | Annotated return type |
| --- | --- | --- |
| Sites | `UserSites(site_reference=None)`, `user_sites(site_reference=None)` | `UserSites` |
| Account | `me(site_reference=None)`, `old_me(site_reference)`, `user_country()` | `Me` |
| Account | `user(site_reference=None)` | `User` |
| Public prices | `prices(start_date=None, resolution="PT15M")`, `country_prices(country, start_date=None, end_date=None, resolution="PT15M")`, `be_prices(start_date=None, end_date=None, resolution="PT15M")`, `fr_prices(start_date=None, end_date=None, resolution="PT15M")` | `MarketPrices` |
| Customer prices | `user_prices(site_reference, user_country, start_date, end_date=None, resolution="PT15M")` | `MarketPrices` |
| Readings and billing | `meter_readings(site_reference)` | `EnergyConsumption \| None` |
| Readings and billing | `month_summary(site_reference)` | `MonthSummary \| None` |
| Readings and billing | `month_insights(site_reference, date)` | `MonthInsights \| None` |
| Readings and billing | `invoices(site_reference)` | `Invoices` |
| Readings and billing | `period_usage_and_costs(site_reference, start_date)` | `PeriodUsageAndCosts` |
| Customer prices | `weighted_average_prices(site_reference, month)` | `WeightedAveragePrices` |
| Contract resolution | `contract_price_resolution_state(connection_id=None)` | `ContractPriceResolutionState \| None` |
| Contract resolution | `contract_price_resolution_request_change(connection_id=None, resolution=None)` | `ContractPriceResolutionChangeResult \| None` |
| Enode | `enode_chargers(site_reference, start_date)` | `EnodeChargers` |
| Enode | `enode_vehicles()` | `EnodeVehicles` |
| Smart Battery | `smart_batteries()` | `SmartBatteries` |
| Smart Battery | `smart_battery_details(device_id)` | `SmartBatteryDetails \| None` |
| Smart Battery | `smart_battery_settings(device_id)` | `SmartBatteryAdjustableSettings \| None` |
| Smart Battery | `smart_battery_sessions(device_id, start_date, end_date)` | `SmartBatterySessions \| None` |
| Smart HVAC | `smart_hvac_status(site_reference)` | `SmartHvac \| None` |
| Smart HVAC | `smart_hvacs(site_reference)` | `list[SmartHvacDevice]` |
| Smart HVAC | `smart_hvac(device_id)` | `SmartHvacDevice \| None` |
| Smart HVAC | `smart_hvac_summary(device_id)` | `SmartHvacSummary \| None` |
| Smart HVAC | `smart_hvac_connect_requests()` | `list[SmartHvacConnectRequest]` |
| Smart PV | `smart_pv_systems()` | `SmartPvSystems \| None` |
| Smart PV | `smart_pv_system_summary(device_id)` | `SmartPvSystemSummary \| None` |
| Smart feed-in | `user_smart_feed_in()` | `UserSmartFeedInStatus \| None` |
| Smart charging | `user_smart_charging()` | `dict[str, object] \| None` |
| App metadata | `app_version()`, `app_notice()` | `dict[str, object] \| None` |
| Rewards | `user_rewards_data()` | `dict[str, dict[str, object] \| None]` |
| Certificates | `tree_certificates()` | `list[dict[str, object]] \| None` |
| Controls | `disable_smart_trading()`, `disable_smart_feed_in()`, `disable_smart_hvac()`, `enode_enable_smart_charging()`, `enode_disable_smart_charging()` | `bool` |
| Settings | `update_user_settings(input_data)`, `enode_update_vehicle_charge_settings(input_data)`, `enode_update_charger_charge_settings(input_data)`, `enode_update_all_vehicle_charge_settings(input_data)`, `smart_hvac_update_settings(device_id, settings)`, `smart_battery_update_settings(device_id, settings)` | `bool` |

### Optional MonthSummary source period

The `MonthSummary.period: str | None` property provides a **validated,
read-only hint** extracted from the existing opaque `_id`. Only the exact
source-ID suffix `|YYYY-MM` is accepted, provided the full identifier has a
single nonempty opaque prefix and a valid four-digit calendar year/month.
For example, `synthetic-site|2026-11` returns `"2026-11"`.

A year-only suffix such as `synthetic-site|2026` returns `None`, as do
invalid calendar years/months, extra separators, trailing characters,
embedded whitespace and unsupported legacy IDs (`summary_123`). The parser
does not expose the private prefix of the source ID, modify the dataclass
fields or constructor, alter the GraphQL query, or create additional API
requests. Both `from_dict()` and `old_from_dict()` return the same
unchanged `MonthSummary` model, including `_id`.

**Evidence limit:** The source-ID suffix shape is based on provider
observations, not an independently documented long-term API contract. A
validated month suffix does not prove complete billing coverage. Consumers
must tolerate `None` and must not substitute the current month or
`lastMeterReadingDate`. The latter can lag the API request, and
`meterReadingDayCompleteness == 1` establishes only that the most recent
meter-reading day is complete, not the entire month. Fetch timestamps
and caching belong to the consuming integration.

Public operations apply their own validation, response parsing, and failure behavior.

- Public price methods can run without credentials. `country_prices()` uses
  the `x-country` header and is called by `be_prices()` and `fr_prices()`.
  `country_prices()` retains `end_date` in its signature while sending only
  the start date and resolution as variables. `user_prices()` requires
  authentication and sends the start date and site reference. Its country
  argument is used for parsing. The price parsers can raise
  `NoMarketPricesAvailableException`, a subclass of `RequestException`.
- Most authenticated methods check `is_authenticated` before making a request.
  `UserSites()`, `old_me()`, and the contract-resolution methods check for an
  `_auth` object. `me()` and `user()` require a nonblank site reference in
  practice, even with their `None` defaults. Validation exceptions differ by
  operation. For example, `invoices()` rejects a blank reference with
  `ValueError`, while `enode_chargers()` uses `FrankEnergieException`.
- Enode, Smart Battery, and Smart HVAC **inventory** methods distinguish a
  successful empty inventory from an invalid or failed response. They
  preserve typed request failures. Smart HVAC detail, summary, and feature
  status can return `None` for an explicit null field.
- `month_summary()` can also return `None` for valid no-data payloads. It
  propagates authentication, network, and rate-limit exceptions and rewraps
  other caught failures in `FrankEnergieException`.
- `period_usage_and_costs()` rewraps request failures in `FrankEnergieException`.
  `month_insights()` preserves typed authentication, network, rate-limit and
  parsing errors; it recognizes one narrowly verified missing-reading error
  as a normal unavailable (`None`) result. The contract-resolution methods return `None` on
  caught request or parsing failures. The boolean controls and settings
  methods return `False` on caught request failures. On success, some check a
  provider result field and others accept a nonempty response without errors.
  Authentication and input checks before these handlers still raise.
  Cancellation propagates.
- `smart_battery_details()` can return `None` on request or parsing failures.
  `smart_battery_settings()` returns `None` on a not-found error or unusable
  settings data while other request errors propagate.
  `smart_battery_sessions()` propagates `RateLimitException` unchanged and
  returns `None` for a not-found error or other caught request failures.
  Its model parsing occurs after the request exception handler.

See the [inventory](../tests/test_device_inventories.py),
[control](../tests/test_smart_controls_mutations.py), and
[contract-resolution](../tests/test_contract_price_resolution_mutations.py) tests.

#### Naming and model access

- Client operations generally use `snake_case`, Python classes use PascalCase,
  and GraphQL operation and field names follow the existing wire format.
  Existing models expose both naming styles where supported. For example,
  `ContractPriceResolutionChangeResult` exposes `effective_date` and
  `effectiveDate`.
- `user_sites(site_reference=None)` delegates to `self.UserSites(site_reference)`
  and returns the same result object or propagates the same exception. The
  legacy operation sends an empty variables dictionary regardless of the
  argument. The parser requires a nonempty site list, fills its top-level
  fields from the first entry, and exposes the parsed entries in
  `deliverySites`. An exception is `UserSites.addressFormatted`: the query
  requests `address.addressFormatted` inside each site, but the parser reads
  `addressFormatted` directly from the first site. For this response shape,
  the top-level field is `None` despite its `str` annotation; the nested
  address remains separate. Other first-entry fields describe the returned
  order. Site selection is up to the caller. The
  [alias tests](../tests/test_user_sites_alias.py) cover forwarding, result
  identity, and error parity.
- Both site methods declare `UserSites` as their return type. On Python
  3.14, default runtime inspection of that annotation resolves to the
  class-local `FrankEnergie.UserSites` method. The methods still return the
  model. Consumer reliance on evaluated annotations needs investigation
  before changing the signatures or model names.
- `DictLikeMixin` gives selected models, such as `Connection`, `EnodeVehicle`,
  `SmartPvSystem`, and `UserSmartFeedInStatus`, legacy read access via
  `obj[key]`, `obj.get(key, default)`, and `key in obj`. A camelCase key is
  normalized to snake_case first, with the original attribute as a fallback.
  Missing bracket keys raise `KeyError`. `get()` returns the default only
  when the key is missing, so an existing attribute set to `None` still returns
  `None`. The mixin implements just these access operations.
- `MarketPrices.electricity` and `MarketPrices.gas` are `PriceData` objects.
  Model-level helpers, fields, constructors, and parsers are observable to
  callers through their existing imports. Examples of covered behavior include
  price interval helpers, status parsing, and nullable fields in
  [model tests](../tests/test_models.py) and [domain tests](../tests/test_domain.py).

#### The two authentication models

| | `authentication.Authentication` (package export) | `models.Authentication` (client runtime type) |
| --- | --- | --- |
| Construction | Slotted dataclass with `auth_token`, `refresh_token`, optional `version=None`, and two optional expiry fields. `authToken` and `refreshToken` are read-only aliases. | Dataclass with `authToken`, `refreshToken`, required `version` accepting `None`, and two optional expiry fields. Construction backfills missing expiry metadata from token claims when available. |
| `from_dict()` | Parses tokens from the nested login or renewal payload, leaving version and expiry fields at their defaults. Malformed payloads can raise `AuthException`. | Parses the tokens and response version. An undecodable token is tolerated with unknown expiry. A decodable token with an unusable `exp` claim raises `AuthException`. |
| Expiry helpers | Has `is_expired` and `is_refresh_token_expired` properties plus `auth_token_valid()` and `auth_refresh_token_valid()` for local expiry checks. | Has `is_expired` for the access token. The refresh expiry is stored as metadata and exposed through the client's `refresh_token_expires_at`. |
| Client use | Independently importable as `python_frank_energie.Authentication`. | The class behind `_auth` and the results of `login()`, `renew_token()`, and deprecated `auth` access. |

Both `is_expired` implementations use a five-minute margin for known expiry.
With unknown expiry, they treat a nonempty token with at least three
dot-separated parts as due for renewal. The expiry values are local hints
for when to renew. The provider determines whether a token is accepted.

#### Compatibility review before moving code

Preserve both import paths and constructor shapes for the authentication
models, and account for their distinct runtime types. Preserve existing
client signatures, awaitability, return shapes and identities where exposed,
model field aliases and dictionary-like access, and operation-specific
exception behavior. Removing a legacy method, model path, accessor, or
publicly named attribute requires an explicit migration decision. Consumer
use of the initialization-only token attributes and direct imports of the
older model classes needs further investigation before such a decision.

### Home Assistant boundary

This package is a standalone Python library. It owns request execution,
in-memory credentials, and parsing of Frank Energie data. Home Assistant
owns its `DataUpdateCoordinator`, `ConfigEntry.runtime_data`, credential
persistence, delivery-site selection, entity/device lifecycle, and update
planning. It decides when to poll, whether to retain previously fetched data
after a failed update, and how to schedule a later attempt after throttling.
These application concerns belong in the separate
[Home Assistant integration](https://github.com/HiDiHo01/home-assistant-frank_energie).

There is one existing runtime boundary leak in the library. Importing
`frank_energie.py` on Windows sets the process-wide asyncio event-loop policy.
Moving that responsibility to the application is a separate proposed step.

## Proposed refactoring sequence

Use one independently reviewed PR per step and characterize existing behavior
before moving it. The sequence records proposed boundaries for issue #177.

### 1. Move event-loop policy to the application

- **Current problem.** Importing the client changes the Windows process-wide
  loop policy. The selected policy can affect the consuming application.
- **Proposed contract and risk.** Importing the library leaves runtime policy
  selection to the caller. Windows applications may currently rely on the
  selector policy installed by the import.
- **Regression tests and readiness.** On Windows, compare the policy before
  and after import in a fresh process. Exercise session creation, request
  cancellation, and cleanup on supported Python versions. Verify the actual
  Windows consumer setup before removing the import-time policy change.

### 2. Consolidate authentication ownership

- **Current problem.** The client uses a different class from the root
  `Authentication` export. Constructor names, parsing, and expiry helpers
  differ, and direct renewal bypasses the lock used by automatic renewal.
- **Proposed contract and risk.** Give credential state and renewal transitions
  one internal owner. Preserve existing import paths and call shapes with
  compatibility adapters where necessary. Changes to class identity,
  constructor defaults, expiry interpretation, or direct renewal concurrency
  require an explicit decision after auditing consumers.
- **Regression tests and readiness.** Cover both constructors and import paths,
  persisted tokens, missing/invalid expiry, the renewal margin, and returned
  types. Cover header construction, concurrent automatic and direct renewal,
  cancellation, invalid refresh, rate limiting, and logout. Agree on the
  compatibility adapters and direct renewal contract before changing state
  representation.

### 3. Separate GraphQL transport from domain operations

- **Current problem.** `FrankEnergie` combines session ownership, HTTP and
  GraphQL classification, renewal coordination, and domain operations.
- **Proposed contract and risk.** Extract request execution and error mapping
  behind the existing client façade after characterizing their dependencies
  on authentication. Keep operation-specific parsing and fallbacks visible
  at the operation boundary. Header order, error precedence, and partial
  responses are sensitive to the placement of that boundary.
- **Regression tests and readiness.** Assert request shape, session ownership,
  timeout, cancellation, exact error types and precedence, `Retry-After`, and
  Smart HVAC and month-summary recovery and redaction. Compare injected and
  internally created sessions. Extract one cohesive responsibility at a time
  once these paths have baseline coverage.

### 4. Split domain model modules behind existing imports

- **Current problem.** `models.py` combines unrelated domains, parsing,
  calculations, and compatibility helpers.
- **Proposed contract and risk.** Group related models internally and keep
  existing re-exports and field access. Moving a class can affect type identity
  and serialization used by consumers. Parser behavior and enum fallbacks can
  change if shared helpers are moved without characterization.
- **Regression tests and readiness.** Verify both import paths, constructors,
  representative parsers and snapshots, nullable fields, timestamp behavior,
  price calculations, and `DictLikeMixin` access. Check any serialization
  formats used by consumers. Move one model family after the imports and
  expected shapes are covered.

### 5. Resolve unused client fields and legacy naming

- **Current problem.** Initialization-only fields can be mistaken for active
  site, resolution, or token state. `UserSites()` retains a legacy name and
  parameter alongside the new alias.
- **Proposed contract and risk.** Keep site selection and request resolution
  explicit at the call boundary. Keep both site-discovery methods and prefer
  `snake_case` for new entry points. Making a placeholder field authoritative
  or removing a legacy argument changes what existing callers can observe.
- **Regression tests and readiness.** Audit downstream usage first. Verify
  alias forwarding, request variables, and exception identity. Cover
  multi-site discovery, explicit site scoping, and public versus customer
  price inputs. If callers inspect return annotations, characterize those
  results on the supported Python versions. Require an agreed migration
  before changing any observable fields or aliases.

## MonthInsights provider-backed nullable contract (issue #266)

`FrankEnergie.month_insights(site_reference, date)` requires an authenticated client,
nonempty site reference and a strict ASCII `YYYY-MM` period (year 0001–9999,
month 01–12). Year-only `YYYY` is not supported. A live year-only probe returned
`monthInsights: null` without a reported error, which does not verify yearly
aggregate support.

In a valid JSON response, provider-supplied `0` remains `0.0`, negative
feed-in costs/usage remain negative, and missing or explicit `null` numeric
fields map to `None`. `gasDifference`, `electricityDifference` and
`feedInDifference` are independently nullable; `gasExcluded=False` does not
imply a non-null gas comparison. Present blocks retain partial null numbers
and `unit=""` distinctly from an absent/null `unit`; malformed non-null
numbers and block types raise sanitized `RequestException` errors.

`lastMeterReadingDate` may be missing/null, or an ISO8601 date/datetime
normalized to UTC; `meterReadingDayCompleteness` and `gasExcluded` remain
optional rather than acquiring fabricated zero/false defaults. The existing
`MonthInsights` and `Difference` field order and constructor arity are retained,
but consumers must now handle `float | None`, `Difference | None`,
`datetime | None` and `bool | None` explicitly. This is a deliberate typing
migration for data fidelity, and consumers such as the Home Assistant
integration must be audited and updated before release.

Both `MonthInsights` and `Difference` expose **writable, typed `snake_case`
property aliases** for their existing camelCase model fields (for example,
`expected_costs_gas`/`expectedCostsGas`, `actual_usage`/`actualUsage`,
and `invoice_id`/`invoiceId`). Both names read and write the same value.
The original camelCase names remain the stored dataclass fields, preserving
existing keyword and positional constructors, `dataclasses.fields()`,
`dataclasses.asdict()`, and `dataclasses.replace()`. The aliases are
properties, not additional serialized fields. Consumers can incrementally
adopt `snake_case` without migrating existing persistence or API call sites.
The SonarQube S116 reports on the legacy fields therefore remain public-API
compatibility exceptions rather than grounds for a breaking rename.

A real `2026-12` query produced `data.monthInsights=null` alongside a single
GraphQL error indicating first/last meter readings were missing, on
`path=["monthInsights"]`. The transport recognizes **only** this observed
error shape (single error, exact path, explicit null payload) as unavailable
and returns `None` without leaking account identifiers. An explicit null
without GraphQL errors is also `None`, but a missing/malformed response,
unknown error or multiple errors remains a sanitized failure. The matching
rule is provider-observation-based, not a guarantee of future API behavior.
