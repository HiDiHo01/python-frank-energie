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
and preserves its network, GraphQL, authentication, rate-limit and
cancellation errors.

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
request with operation name `WeightedAveragePrices`. The provider's
**actual response schema, nullability, values, currency/pricing semantics,
and populated items have not yet been verified** against a live response.
The regression fixtures are entirely synthetic and demonstrate parser
behavior, not provider-confirmed values.

In particular, `averageMarketPricePlus` should not be described as
including any specific taxes or markups without provider evidence.
These are weighted-price fields as named by the provider, not synonyms
for the `averageElectricityPrices` fields of `MarketPrices`.
The API surface is additive; no existing pricing operation is changed.
