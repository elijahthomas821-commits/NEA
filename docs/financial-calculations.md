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

## 8. What these numbers are not

They are estimates from the evidence recorded so far, with the assumptions above. Every
evaluation stores its inputs: the configuration versions, the comps and their weights, every
cost line and the reason codes. You can see exactly why a number came out as it did, but no
result is a guarantee.
