# F7 — the sign-side key-type guard changes the root's behavior; ship it in this pr anyway

## .the fork
- (a) ship the guard here: `createSecureDistributedAuthToken` throws when the private key's type does not fit the alg
- (b) hold the guard for its own pr, and keep this pr to the subpath alone, as the wish's "root contract unchanged" reads strictly

## .taken
(a).

- the root's exported names, `main`, and every well-typed call stay as they were; only a call that pairs an alg with a key of the other family changes, from a silent mismatched sign to a loud error
- that call has no correct outcome to preserve: the token claims an alg its signature does not use
- the skipped tests on main already named this as the intended behavior (`throw an error`)
- three peer lanes graded the pin a blocker; (b) would hold the pr on a gap they agree is a defect

## .rework
clean: one guard paragraph and one transformer; a revert restores the prior sign path, and the two tests flip.

## .confidence
75%. doubt: the commander may read "root contract unchanged" to cover behavior too, and want the guard in its own release note.

## .where
`src/signingAlgorithm/createVerifiableSignature.ts`; readme note after the `createSecureDistributedAuthToken` example; pr body names it for the commander

## .verdict
best-guessed; open for commander review in the pr body
