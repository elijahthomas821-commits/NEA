# Financial calculations

How the platform turns a listing into a resale estimate, a profit, an ROI and a maximum
purchase price. Every number in the worked examples below is checked by the test suite
(`tests/unit/test_profit.py`, `test_comps.py`, `test_market_stats.py`, `test_velocity.py`), so
this document cannot silently drift from the code.

All example fees use the **placeholder** Vinted values shipped in `fees.yaml` (Buyer Protection
£0.70 + 5 %, postage £2.99, no selling fee, £0.50 packaging, 2 % refund allowance). Check them
against Vinted's current fees before relying on any result.

## 1. Money rules

- Money is `Decimal`, never binary floating point. Passing a `float` where money is expected
  raises an error.
- Each fee is rounded **half-up to the penny**, because that is how a marketplace charges it.
  Totals are exact sums of those pennies. Ratios (ROI, weights, confidence) keep full precision.
- Values are rounded half-up to 2 dp only for display and storage.
- The maximum purchase price is always rounded **down** to the penny.
- AI output never contains, and never feeds into, any money value.

## 2. Fees

```
fee(amount) = round_half_up( clamp( fixed + variable(amount), min_fee, max_fee ), 0.01 )
variable    = percent × amount                      (simple rule)
            = Σ tier.percent × (part of amount in the tier's band)   (tiered rule)
```

Tiers are marginal, like tax bands: with 10 % up to £100 and 5 % above, a £150 sale pays
£10.00 + £2.50. Every fee function is non-decreasing in the amount (the max-price search
depends on this).

| Item price | Buyer Protection (0.70 + 5 %) |
| --- | --- |
| £45.00 | 0.70 + 2.25 = **£2.95** |
| £74.87 | 0.70 + 3.7435 = 4.4435 → **£4.44** |
| £10.10 | 0.70 + 0.505 = 1.205 → **£1.21** |

## 3. Cost model, profit and ROI

```
total_acquisition_cost = purchase_price + buyer_fee(purchase_price) + inbound_shipping
                       + cleaning + repairs + other_acquisition
selling_costs(sale)    = selling_fee(sale) + outbound_shipping_paid_by_seller + packaging
                       + expected_refunds(sale) + other_selling
expected_refunds(sale) = round_half_up(sale × expected_refund_rate)
net_proceeds           = sale − selling_costs(sale)
net_profit             = net_proceeds − total_acquisition_cost
ROI                    = net_profit / total_acquisition_cost
```

ROI is measured on everything you pay to acquire the item, not on the listing price.

**Worked example: buy at £45.00, resell at £110.00**

| Line | Amount |
| --- | --- |
| Purchase price | £45.00 |
| Buyer Protection fee | £2.95 |
| Postage to you | £2.99 |
| **Total acquisition cost** | **£50.94** |
| Sale price | £110.00 |
| Selling fee | £0.00 |
| Packaging | £0.50 |
| Expected refunds (2 %) | £2.20 |
| **Net proceeds** | **£107.30** |
| **Net profit** | 107.30 − 50.94 = **£56.36** |
| **ROI** | 56.36 / 50.94 = **110.6 %** |

## 4. Maximum purchase price

The largest price *P* (whole pennies, rounded down) such that all of these hold:

| | Constraint | Config |
| --- | --- | --- |
| (a) | profit(P) ≥ min_profit | `deal_rules.min_profit` |
| (b) | ROI(P) ≥ min_roi | `deal_rules.min_roi` (optional) |
| (c) | P ≤ price cap | `deal_rules.max_purchase_price` |
| (d) | total_acquisition_cost(P) ≤ capital cap | `deal_rules.max_capital_per_item` |

Net proceeds *N* do not depend on *P*, so (a), (b) and (d) are all upper bounds on the cost:

```
cost(P) ≤ C = min( N − min_profit,  N / (1 + min_roi),  capital_cap )
```

For a linear buyer fee `fixed + pct·P`:

```
P ≤ (C − fixed − shipping − extras) / (1 + pct)
```

Because the fee is rounded to the penny, the closed form can be one penny out either way, so
the result is then corrected to the exact largest price that fits. Tiered or capped fees use an
exact binary search over whole pennies instead; the two methods agree for linear fees
(property-tested). The expected sale price (median) is the default resale basis. Set
`deal_rules.resale_basis: quick` to use the quick-sale price (P25) for a more conservative
maximum.

**Worked example: expected resale £110.00, min profit £25, min ROI 30 %, cap £300**

```
N           = 107.30                           (from section 3)
(a)         cost ≤ 107.30 − 25        = 82.30
(b)         cost ≤ 107.30 / 1.30      = 82.538…
C           = 82.30                             → min profit is the binding constraint
closed form P ≤ (82.30 − 0.70 − 2.99) / 1.05 = 74.866… → £74.86
correction  P = £74.87: fee = 4.4435 → £4.44, cost = 74.87 + 4.44 + 2.99 = 82.30 ≤ 82.30 ✓
            P = £74.88: fee = 4.444  → £4.44, cost = 82.31 > 82.30 ✗
maximum     £74.87 (profit at that price: exactly £25.00)
```

If even £0.01 does not fit (fixed costs alone exceed the target), the result is **no viable
purchase price**.

## 5. Comparable sales (resale estimate)

Prices come only from **completed sales** ("comps"). Your price guide is a separate, clearly
labelled last resort (section 6).

### 5.1 Eligibility

A sale is excluded, with a recorded reason, if it:

- was sold after the evaluation time (so re-running an old evaluation cannot see the future);
- is older than `market.window_days` (default 365);
- is a last-asking-price observation and `last_asking_price.use_for_price` is off;
- is in another currency and no FX rate is on record within `fx_max_age_days` of the sale date.

### 5.2 Fallback hierarchy

The first level whose sample size ≥ `min_sample_size` (3) **and** effective sample size
≥ `min_effective_n` (5) is used:

| Level | Comps must match | Adjusted for |
| --- | --- | --- |
| L1 | product, size, condition, colour | — |
| L2 | product, size, condition | — |
| L3 | product, condition | size |
| L4 | product | size, condition |
| L5 | brand, category, condition | size |
| L6 | brand, category | size, condition |

A listing matched only to "brand × category (any model)" starts at L5. Category-only data is
never used for price. If no level qualifies there is no estimate, and the listing is rejected
with `INSUFFICIENT_MARKET_DATA` unless your price guide covers it.

### 5.3 Normalising each comp to the listing

```
adjusted = price × fx_rate × haircut × condition_ratio × size_ratio
condition_ratio = multiplier(listing condition) / multiplier(comp condition)
size_ratio      = multiplier(listing size) / multiplier(comp size)    (1 if either unknown)
haircut         = 0.92 for last-asking-price observations, else 1
```

Examples (seed multipliers): a **good** comp sold at £85 is worth 85 × 1.00 / 0.85 = **£100.00**
for a *very good* listing; an **XXL** comp at £100 is worth 100 × 1.00 / 0.92 = **£108.70**
for an *L*. Comps with no recorded condition are treated as *good* and down-weighted.

### 5.4 Weights

```
weight   = recency × trust × match_confidence
recency  = 0.5 ^ (age_days / half_life_days)                  (half-life 90 days)
trust    = source_trust × marketplace_trust × row_trust
           × 0.6 for last-asking-price observations
           × 0.8 if the comp's condition is unknown
```

Example: a manual-entry Vinted comp sold 10 days ago has recency 0.5^(10/90) = 0.92587 and
trust 0.8 × 1.0 = 0.8, so weight 0.74070.

**Effective sample size** (Kish): `n_eff = (Σw)² / Σw²`. It equals *n* when all weights are
equal and falls towards 1 when one comp dominates. For example, 3 recent comps and 3 comps
300 days old give n_eff < 5.

### 5.5 Outliers

Adjusted prices outside the fences are flagged as outliers and left out of the statistics.
They are never deleted.

- *n* ≥ 8: Tukey fences Q1 − 1.5·IQR and Q3 + 1.5·IQR.
- 4 ≤ *n* < 8: median ± 3 × 1.4826 × MAD (robust for small samples).
- Fewer than 4 comps, or zero spread: nothing is flagged.

### 5.6 Weighted percentiles

Sort the values. Value *i* gets the plotting position `p_i = (W_before_i + w_i/2) / W`. Then
interpolate linearly between positions and clamp at the ends. With equal weights this is the
Hazen definition, `p_i = (i + 0.5)/n`.

Example (weights 1, 1, 2 on £90, £100, £130): positions 0.125, 0.375, 0.75, so the median
(q = 0.5) is 100 + 30 × (0.125 / 0.375) = **£110**.

Six equal-weight comps (£90, 95, 100, 105, 110, 120) give **P10 £90.50, P25 £95.00,
median £102.50, P75 £110.00, P90 £119.00** and dispersion (P75 − P25)/median = **0.146**.

| Estimate | Default percentile |
| --- | --- |
| Quick sale | weighted P25 |
| Expected | weighted median |
| Optimistic | weighted P75 |

### 5.7 Estimate confidence

The confidence is the weighted geometric mean of five factors, each between 0 and 1:

| Factor | Formula | Weight |
| --- | --- | --- |
| Sample | n_eff / (n_eff + 5) | 1 |
| Level | L1 1.00, L2 0.95, L3 0.85, L4 0.75, L5 0.55, L6 0.45 (price guide 0.25) | 1 |
| Dispersion | 1 / (1 + (IQR/median) / 0.5) | 1 |
| Recency | weight-averaged recency of the comps | 0.5 |
| Match | confidence the listing is the product the comps describe | 1 |

```
confidence = exp( Σ weight·ln(factor) / Σ weight )
```

Example: six identical L1 comps sold 10 days ago, match 0.9 → factors 6/11, 1, 1, 0.9259, 0.9
→ confidence **0.846**. The formula is deliberately simple and will be calibrated against your
recorded outcomes (predicted vs actual sale prices).

## 6. Price guide (your own reference ranges)

The price guide is used only when no comparable-sales level qualifies. Each entry gives a
low / typical / high range for a brand, category and optionally a product, at a stated
condition. Quick / expected / optimistic are that range, adjusted to the listing's condition
and size. The estimate has a fixed low confidence (`market.price_guide.confidence`, default
0.25), is labelled "your price guide" everywhere, and is capped at the REVIEW tier by default
(`deal_rules.caps.price_guide`).

## 7. Sale velocity

Median days to sale comes from the **Kaplan–Meier** estimator over:

- comps that have both a listing date and a sale date (events);
- your own unsold listed stock in the same scope (censored: "at least N days so far").

Using completed sales alone would overstate the speed (survivorship bias).

```
S(t) = Π over sale times ≤ t of (1 − sold_at_t / at_risk_t);   median = first t with S(t) ≤ ½
```

Example: sales after 3, 5 and 7 days → median 5. Add three unsold items listed for 20, 25 and
30 days → S(3) = 5/6, S(5) = 4/6, S(7) = 3/6 → median **7**. If more than half have not sold,
the median is "not reached" and velocity is unknown.

Scopes are tried in order: the pricing level's comps, then brand × category, then category
only. At least 3 events are needed.

```
speed     = clamp(1 − median_days / (2 × target_days), 0, 1)      (target 30 days)
volume    = sales_90d / (sales_90d + 10)
liquidity = 0.6 × speed + 0.4 × volume                             (high ≥ 0.66, medium ≥ 0.33)
sell-through proxy = sales_30d / (sales_30d + active listings observed)
```

"Active listings observed" counts only listings you have submitted, so it undercounts the
real market and is labelled "observed".

## 8. Authenticity risk

This is a risk assessment, never a certification. It starts from the brand's base risk (the
prior share of counterfeits for that brand, set in `brands.yaml`), and every signal shifts the
odds:

```
logit(risk) = logit(base risk) + Σ shifts          risk = 1 / (1 + e^(−logit))
```

A shift of +0.7 roughly doubles the odds and −0.7 roughly halves them. Placeholder values are
in `authenticity.yaml`:

| Raises risk | Shift | Lowers risk | Shift |
| --- | --- | --- | --- |
| Replica / look-alike wording | +4.0 | Checklist item seen in photos | about −0.5 each |
| Price < 35 % of comps median | +2.0 | Seller marked as trusted | −1.0 |
| Same photo on another seller's listing | +2.0 | Established seller (≥ 50 reviews, ≥ 4.8) | −0.5 |
| Checklist item looks questionable | +1.2 | Price in the normal range | −0.2 |
| Price < 50 % of comps median | +0.8 | | |
| Brand inferred from photos (mislabel) | +0.8 | | |
| "No tags", "label cut"… | +0.6 | | |
| Contradictory details, new account, few reviews, low rating | +0.3 … +0.5 | | |

Buying below market is the point of flipping, so only extreme under-pricing counts as a
warning.

Example: Stone Island (base 0.35), price 41 % of the median (+0.8), established seller (−0.5),
four checklist items seen (−2.08). The logit is −0.62 + 0.8 − 0.5 − 2.08 = −2.40, so the risk
is **0.083** (low).

**Confidence** says how much could actually be checked: 0.20, plus 0.05 per photo (up to
+0.20), plus 0.10 per checklist item seen, plus small bonuses for seller details and market
data. It is capped at 0.35 with no photos and at 0.90 overall.

## 9. Deal rules

Rules are configuration (`deal_rules`, versioned). The decision is made in three steps.

1. **Hard gates reject**, each with a reason code:
   - listing not active, missing price or unsupported currency;
   - unknown brand or category, category out of scope, kids' size;
   - replica wording, or a seller you blocked;
   - insufficient market data;
   - profit, ROI or identification confidence below your minimum;
   - evidence-driven counterfeit risk above the maximum;
   - median sale time over the maximum;
   - price or total cost above the cap;
   - inventory exposure or units of this product above the limit.
2. **Near misses go to REVIEW.** If every failed gate is a numeric threshold missed by less
   than `review.near_miss_pct` (10 %), the listing is sent as REVIEW instead of rejected.
3. **Tiers.** A listing that passes every gate is HIGH priority if it also meets the stricter
   `high_priority` thresholds and has none of these: a severe price anomaly, damage wording or
   a suspected re-listing. Otherwise it is NORMAL. Caps then limit the best reachable tier:

| Situation | Best tier |
| --- | --- |
| Brand inferred from photos of an unbranded listing | NORMAL |
| Priced from your price guide, not sales data | REVIEW |
| AI help was needed for identification but unavailable | NORMAL |
| Sale speed unknown | NORMAL |
| Contradictory details | REVIEW |
| Risk high only because of the brand prior, or too little evidence to check | REVIEW ("ask for photos") |

A counterfeit risk above `max_authenticity_risk` rejects the listing only when warning signs
add at least `auth_reject_min_warning` (1.0) to the log-odds. When the risk comes mostly from
the brand's base rate, you get REVIEW with the checks to make. Low check confidence also leads
to REVIEW by default (`low_auth_confidence_action: review`).

## 10. Recording a purchase

The system never buys anything. After you buy an item yourself and confirm it in Telegram, the
purchase records what you actually paid:

```
total_acquisition_cost = item price + Buyer Protection fee + postage + other
```

The fee and postage are first estimated from your `fees` settings (buy at £45.00: £2.95 +
£2.99, total £50.94) and you can replace them with what checkout charged:

- **one amount** is the total you paid: the fee estimate is kept (capped at total − item
  price) and postage is the rest. A total of £51.20 → fee £2.95, postage £3.25.
- **two amounts** are the fee and the postage: `2.95 3.49` → total £51.44.

The purchase keeps a snapshot of the prediction, so it can be checked once the item sells:

```
expected_profit_at_purchase = expected net proceeds (from the evaluation) − actual total cost
predicted_ROI               = expected_profit_at_purchase / actual total cost
```

With the section 3 example, if checkout charged £51.20: 107.30 − 51.20 = **£56.10** expected
profit, ROI 56.10 / 51.20 = **109.6 %**. Cleaning and repairs are added to the inventory item
later, not to the purchase.

**Bundles.** When several items are bought together, the purchase total (items, fee, postage,
other) is split across them:

- `expected_value` (default): in proportion to each item's expected resale price;
- `equal`: the same share each;
- `manual`: the amounts you give, which must add up to the total exactly.

Each share is rounded down to the penny and the leftover pennies go, one each, to the items
with the largest remainders (earlier items first on ties), so the shares always add up to the
total and each is within a penny of its exact proportion. Example: £100.00 split by expected
prices £90 / £60 / £30 → £50.00, £33.33, £16.67; £10.00 split equally three ways → £3.34,
£3.33, £3.33. An item's expected profit is its evaluation's expected net proceeds minus its
share.

## 11. Selling: net proceeds and the outcome

```
net_proceeds  = sale_price + postage charged to the buyer − selling fees
                − postage you paid − refunds − other selling costs
profit        = net_proceeds − cost basis   (purchase share + cleaning + repairs + other)
ROI           = profit / cost basis
```

Costs you don't give default to your `fees` settings for the channel: on Vinted no selling fee,
no postage paid by you, and the £0.50 packaging placeholder. Refunds default to zero (the
expected-refund allowance in section 3 is only for estimates).

The prediction made at purchase is then scored: price error = actual − predicted expected price
(and as a percentage of the prediction), whether the price fell between the predicted
quick-sale and optimistic prices, profit and days-to-sale (listing → sale, or purchase → sale
if never listed). A written-off item scores a loss of its whole cost basis (ROI −100 %). Later
changes (a refund, extra costs, a corrected price) re-score it; a cancelled sale withdraws the
score. Your sale also becomes a comparable sale (`own_sale`, the most trusted kind), unless the
item was never identified to a brand and category.

Example: item cost £35.00 (£30.00 share + £5.00 cleaning), listed 4 Sep, sold 14 Sep for
£60.00 plus £3.00 postage charged, with £1.50 fees, £3.00 postage paid and £0.50 packaging →
net £58.00, profit **£23.00**, ROI **65.71 %**, 10 days; predicted £65 (quick £55, optimistic
£75) → error −£5.00 (−7.69 %), within the range.

## 12. What these numbers are not

They are estimates from the evidence recorded so far, with the assumptions above. Every
evaluation stores its inputs: the configuration versions, the comps and their weights, every
cost line and the reason codes. You can see exactly why a number came out as it did, but no
result is a guarantee.
