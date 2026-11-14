# F6 — the two key-type skips: pin today's behavior, or add the guard

## .the fork
- (a) add a key-type guard to `createVerifiableSignature`, then un-skip the two cases as written (`throw an error`)
- (b) replace each skip with a test that pins today's outcome (`{ threw: null, verified: true }`), and catch the guard as a dream

## .taken
(b) at first; overturned to (a) on the sign side. see `.verdict`.

## .rework
clean: the guard is one check in one file, with its own snap; a revert flips the two tests back.

## .confidence
85% on (b) at the call. doubt held: a peer could judge the mismatch a defect the skips existed to catch.

## .where
`src/signingAlgorithm/createVerifiableSignature.ts`, `src/signingAlgorithm/getKeyTypeOfAlg.ts`, `src/signingAlgorithm/createVerifiableSignature.test.ts`; the verify side stays in dream `.dream/v2026_11_06.repair.signature-key-type-guard.md`

## .verdict
overturned by peer review at 5.3 (r2 ergo-contract-snapshots, r4 ergo-acceptance-journey-coverage, r8 mech-test-intent): a pin that asserts `verified: true` for a wrong-type key inverts the intent the skipped tests named, so a reader trusts a gap as a contract. (a) taken on the sign side: a key whose type does not fit the alg throws `SimpleJwtAuthError`. the root behavior change this makes is fulcrum F7.
