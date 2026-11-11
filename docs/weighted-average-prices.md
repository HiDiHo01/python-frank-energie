# Weighted average prices

The asynchronous `FrankEnergie.weighted_average_prices(site_reference, month)`
operation uses the provider's **WeightedAveragePrices** GraphQL selection.
It retrieves *reported* weighted market prices for the three categories
`gas`, `electricity` and `feedIn`, with individual subperiod items.
The library does not calculate or recompute these averages.

## Request

The observed GraphQL request used `date: "2025-03"` (a calendar-month
string) and a site reference. The public method validates the `YYYY-MM`
format, calendar month, and nonempty site reference before the request.
The exact range of other date formats accepted by the provider is unknown.

```python
async with FrankEnergie() as api:
    await api.login(username, password)
    prices = await api.weighted_average_prices(
        site_reference=site_reference,
        month="2025-03",
    )
```

Pass credentials and site references securely at runtime. The method requires
authentication, sends a request through the existing shared GraphQL transport,
and preserves existing network, authentication, rate-limit and
cancellation error classifications. Weighted-price failures are redacted
before the shared HTTP and GraphQL transport can log provider details.
Known GraphQL validation failures retain their exception class. Unknown
GraphQL errors are rejected without exposing upstream response content;
known failures retain their order of precedence. A malformed JSON body,
an unexpected JSON content type, or an invalid GraphQL `errors` container
raises a privacy-safe `RequestException` for this operation. Errors in
automatic `RenewToken` requests are redacted at the same transport boundary,
while recognized authentication, refresh-token and rate-limit categories
retain their existing classifications.

## Result models

The models are exported from the package root as
`WeightedAveragePrices`, `WeightedAveragePriceCategory` and
`WeightedAveragePriceItem`; they are defined in
`python_frank_energie/weighted_average_prices.py`.

| GraphQL field | Python model attribute |
| --- | --- |
| `weightedAveragePrices._id` | `WeightedAveragePrices._id` |
| `gas` | `WeightedAveragePrices.gas` |
| `electricity` | `WeightedAveragePrices.electricity` |
| `feedIn` | `WeightedAveragePrices.feed_in` |
| `averageMarketPrice` | `average_market_price` |
| `averageMarketPricePlus` | `average_market_price_plus` |
| `perUnit` | `per_unit` |
| `items` | `list[WeightedAveragePriceItem]` |
| `items[]._id` | `WeightedAveragePriceItem._id` |
| `items[].date` | `WeightedAveragePriceItem.date` |
| `items[].from` / `items[].till` | `from_time` / `till_time` |

Category values may be explicitly `null`, represented by `None`.
Selected numeric values and units also preserve explicit `null`, rather
than silently becoming zero or an empty string. A missing selected key,
invalid container or non-finite numeric value raises `RequestException`.
An explicitly returned `items: []` is preserved. Time fields remain the
original provider strings; the library does not guess their time zone.

## Provider verification and scope

The **GraphQL selection and variable shape** came from a user-supplied
request with operation name `WeightedAveragePrices`. A read-only live
response for **March 2025**, provided on 2026-11-11, confirmed:

- A nonempty period `_id` containing a site reference and month. The real
  reference and item identifiers are deliberately omitted here.
- `gas: null` and `feedIn: null`, while `electricity` contained the
  monthly `averageMarketPrice`, `averageMarketPricePlus`, `perUnit: "KWH"`,
  and `items` with **31 daily records**.
- Each item contained `_id`, calendar `date`, UTC `from` and `till`
  strings, both numeric price fields, and `perUnit: "KWH"`.
- The **2025-03-30** entry covered **23 hours**: from
  `2025-03-29T23:00:00.000Z` to `2025-03-30T22:00:00.000Z` because
  Europe/Amsterdam entered daylight-saving time. Daily `from`/`till`
  values must not be assumed to span exactly 24 hours.
- A daily `averageMarketPrice` was negative while the corresponding
  `averageMarketPricePlus` was positive. Preserve each value rather than
  clamping negative prices.

These observations confirm the **populated electricity result structure**
and explicitly null gas/feed-in for one site/month. They **do not** establish
the behavior of populated gas/feed-in categories, null numeric fields,
absence of a category, or whether `averageMarketPricePlus` includes
specific taxes/charges. The regression test recreates the observed
31-day/DST shape with **entirely synthetic IDs and prices**, not a copy
of the user's raw response.

In particular, `averageMarketPricePlus` should not be described as
including any specific taxes or markups without provider evidence.
These are weighted-price fields as named by the provider, not synonyms
for the `averageElectricityPrices` fields of `MarketPrices`.
The API surface is additive; no existing pricing operation is changed.
