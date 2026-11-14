# F12 — the graph walker splits into its transformers and its dpdm call

## .the fork
- (a) ship `getAllExternalDepsOfEntry.ts` (230) with its integration test (217) in one layer: ~525 weighted, over the bar
- (b) cut L8–145, the pure transformers over a dpdm tree, into `asExternalDepsOfDpdmTree.ts` with a new unit test (W1); the dpdm call and its cases follow (W2, W3)
- (c) ship the transformers in W1 with no test of their own, covered only once W2 lands

## .taken
(b). (c) lands code with no test in its own pr. (b) costs ~100 new test lines that #21 does not hold today.

## .rework
clean: the cut follows the file's own seam (transformers above L146, the communicator below); no caller outside `src/.test/` imports them.

## .confidence
80%. doubt: the new unit test is new work, so W1 is the one layer not cut from #21 as is.

## .where
`split-plan.md` W1, W2, W3

## .verdict
best-guessed; open for director review
