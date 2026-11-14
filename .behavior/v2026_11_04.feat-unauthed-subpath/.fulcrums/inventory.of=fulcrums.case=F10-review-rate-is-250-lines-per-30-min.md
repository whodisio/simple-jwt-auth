# F10 — the review rate: 250 weighted lines per 30 min

## .the fork
- (a) 250 lines per 30 min: the 500 lines/hr upper bound of the smartbear/cisco peer-review study (defect yield falls off past it; sessions over 400 lines lose effect)
- (b) a faster rate (e.g. 400 lines per 30 min), fewer layers, each read less closely
- (c) a slower rate (200–300 lines/hr, the study's sweet spot), about twice the layers

## .taken
(a). it is the one published rate at hand, and its upper bound already favors fewer prs.

## .rework
clean: the plan is a table. another rate re-cuts the table; no code is built on it yet.

## .confidence
75%. doubt: the 30-min bar may assume a reader who already knows the wish, who reads faster; or a slower reader, which (c) serves.

## .where
`split-plan.md` `.the review budget`

## .verdict
best-guessed; open for director review
