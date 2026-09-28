# Analytics: definitions

Every number on `/analytics/*` and in the Telegram `/stats` and `/stock` replies is defined here.
The worked example at the end is pinned by `tests/unit/test_analytics.py`, so these definitions
and the code can't drift apart.

## Conventions

- **Currency.** Only items bought in your base currency (`BASE_CURRENCY`, default GBP) are
  counted; the summary reports how many items are in other currencies.
- **Periods.** `from` and `to` are UTC calendar days, both inclusive. Leave either out for an
  open-ended period.
- **Rounding.** Money totals are exact sums. Averages are rounded half-up to the penny. Ratios
  (ROI, margin, rates) have four decimal places, e.g. `0.3999` = 39.99 %.
- **Cost basis** of an item = its share of the purchase (bundles are split, see
  `docs/financial-calculations.md` §10) + cleaning + repairs + other costs.
- **Estimates** (expected resale prices) are labelled as such and never mixed into realised
  figures.

## Profit and loss (for a period)

| Metric | Definition |
| --- | --- |
| items bought, spend | items whose purchase date is in the period; spend = Σ their purchase share |
| items sold | items whose sale date is in the period (a cancelled sale doesn't count) |
| revenue | Σ sale prices |
| net proceeds | Σ (sale price + postage charged to the buyer − selling fees − postage you paid − refunds − other selling costs) |
| cost of sold | Σ cost basis of the items sold |
| realised profit | net proceeds − cost of sold |
| ROI | realised profit ÷ cost of sold |
| margin | realised profit ÷ revenue |
| average / median profit | per item sold |
| win rate | share of items sold at a profit (> £0) |
| average days to sell | purchase date → sale date |
| median days listed → sold | for items with a listing date |
| written off, write-off loss | items written off in the period; loss = their whole cost basis |
| returned, return loss | items sent back to the seller in the period. The purchase is assumed refunded, so the loss is only the cleaning, repair and other costs you recorded (e.g. return postage) |
| net result | realised profit − write-off loss − return loss |
| sell-through | items sold ÷ (items sold + items still in stock at the end of the period) |

## Stock (today)

| Metric | Definition |
| --- | --- |
| items, capital tied up | items ordered, in transit, received, needing work, ready to list or listed; capital = Σ cost basis |
| expected value | Σ expected resale prices where known (an estimate); items without one are counted |
| by status | item count per status |
| ageing | items and capital by days since purchase: 0–30, 31–60, 61–90, 90+ |
| average days listed | for listed items, listing date → today |

## Breakdowns

`/analytics/breakdown?by=brand|category|month|decision|comp_level` groups the period's sales
(same metrics as above) by brand, category, sale month, the evaluation's decision when you
bought the item (HIGH / NORMAL / REVIEW...), or the comparable-sales level behind the estimate.
Items with no value are grouped as `unknown`. The groups always add up to the P&L totals.

## Prediction accuracy

Each purchase keeps the evaluation's prediction; a sale or write-off records the outcome
(`docs/financial-calculations.md` §10–11). Accuracy is measured on **sales resolved in the
period** (a write-off has no sale price to compare):

| Metric | Definition |
| --- | --- |
| mean absolute error | mean of \|actual sale price − predicted expected price\| |
| mean absolute % error | mean of \|actual − predicted\| ÷ predicted |
| bias | mean of (actual − predicted): negative means the estimates run high |
| within range | share of sales between the predicted quick-sale and optimistic prices |
| mean profit error | mean of (actual profit − predicted profit) |
| mean days error | mean of (actual days listed → sold − predicted median days) |

Grouped by comparable-sales level and by basis (comps vs your price guide).

## Funnel

Listings added → evaluations (by decision) → alerts sent (by priority) → your BUY / PASS /
REVIEW decisions → purchases (and how many came from an alert). **Buy rate** = purchases
linked to an alert ÷ deal alerts sent (high, normal and review; "not a deal" replies are
excluded). Also the AI requests made and their cost in USD.

## Exports

`/analytics/export/{inventory,sales,evaluations}.csv` (period-filtered; at most 50 000 rows).
Text that a spreadsheet would treat as a formula (starting with `=`, `+`, `-`, `@`) is written
with a leading apostrophe, so opening an export can never run anything a listing title
contained.

## Worked example (September 2026, as of 5 October)

| Item | Bought | Cost basis | Listed | Outcome |
| --- | --- | --- | --- | --- |
| A | 20 Aug | £50.94 | 25 Aug | sold 5 Sep: £110.00, net £107.30 |
| B | 2 Sep | £30.00 + £5.00 cleaning | 4 Sep | sold 14 Sep: £60.00, net £57.00 |
| C | 3 Sep | £80.00 | 6 Sep | sold 26 Sep: £70.00, net £68.00 |
| D | 10 Sep | £40.00 | 12 Sep | listed (expected £90) |
| E | 15 Sep | £25.00 + £3.00 | — | written off 20 Sep |
| F | 18 Sep | £45.00 + £2.00 | — | returned 22 Sep |
| G | 1 Jun | £60.00 | 10 Jun | listed (no estimate) |
| H | 28 Sep | £35.00 | — | ordered (expected £70) |
| I | 5 Sep | £20.00 | — | sold 2 Oct (after the period) |

- Bought in September: B, C, D, E, F, H, I → 7 items, spend £275.00.
- Sold: A, B, C → revenue £240.00, net proceeds £232.30, cost of sold £165.94.
- Realised profit 232.30 − 165.94 = **£66.36**; ROI 66.36 / 165.94 = **39.99 %**; margin
  66.36 / 240 = **27.65 %**.
- Profits 56.36, 22.00, −12.00 → average £22.12, median £22.00, win rate 2/3 = 66.67 %.
- Days to sell 16, 12, 23 → average 17.0; days listed → sold 11, 10, 20 → median 11.0.
- Write-off loss £28.00 (E); return loss £2.00 (F's extras); net result 66.36 − 28 − 2 =
  **£36.36**.
- In stock on 30 September: D, G, H, I → sell-through 3 / (3 + 4) = **42.86 %**.
- Stock on 5 October: D, G, H → £135.00 tied up, expected value £160.00 (G has no estimate);
  ageing: 0–30 days 2 items (£75.00), 90+ days 1 item (£60.00); average days listed
  (23 + 117) / 2 = 70.0.
- Predictions for A, B, C (predicted 110, 65, 100; actual 110, 60, 70): mean absolute error
  (0 + 5 + 30) / 3 = £11.67, bias −£11.67, mean absolute % error 12.56 %, within range 2 of 3.
