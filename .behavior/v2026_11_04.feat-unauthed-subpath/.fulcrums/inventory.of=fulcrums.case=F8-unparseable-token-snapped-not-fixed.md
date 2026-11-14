# F8 — an unparseable jwt-shaped token: snap and document the raw SyntaxError, not fix it

## .the fork
- (a) wrap the decode ops' `JSON.parse` so `a.b.c` throws `SimpleJwtAuthError`, on the subpath and the root alike
- (b) pin today's raw `SyntaxError` in an acceptance snap, name it in the readme, and catch the fix as a dream

## .taken
(b).

- the subpath re-exports the root's own decode ops; (a) changes the root's thrown class for every caller that catches `SyntaxError` today
- the wish moves the decode ops to a lean entry; it does not ask to change what they throw
- the snap makes the behavior visible, so a later fix shows as a diff

## .rework
clean: the fix lands in its own pr; the t4 case flips its expected class.

## .confidence
85%. doubt: a peer may hold that a browser consumer now meets this on a new path and wants the loud class.

## .where
`src/unauthed.acceptance.test.ts` case2 `[t4]`; readme subpath section; dream `.dream/v2026_11_06.repair.decode-ops-throw-raw-syntaxerror.md`

## .verdict
best-guessed; open for commander review in the pr body
