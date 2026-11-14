# F4 — clamp walks the static graph of built `dist/`

## .the fork
- (a) static walk of every `require()` in emitted js from `dist/unauthed.js` (dpdm, a devDep already, or a small walker)
- (b) runtime: spawn node, `require('dist/unauthed.js')`, read `require.cache`
- (c) walk `src/` ts instead of `dist/` js

## .taken
(a). bundlers walk the static graph, so a static walk models what ships. (b) misses lazy requires in function bodies (`importCrypto.ts` holds one). (c) counts `import type` lines that emit erases, so it would cry wolf on `getUnauthedHeaderClaims`.

the assertion is an allowlist (`{ buffer }`), not only a denylist of the six wish deps: a denylist misses a heavy dep no one has named yet. the six stay named in the assertions, so the wish's floor reads plainly.

## .rework
clean: one test file.

## .confidence
90%.

## .where
a new test beside `src/contract.acceptance.test.ts` (it needs `dist/`)

## .verdict
open
