# F1 — subpath reach: stub dir `unauthed/package.json`, no `exports` map

## .the fork
- (a) `exports` map only — ts `node10` (every target whodis lib) ignores it; fails the wish
- (b) `exports` map plus `typesVersions` — fixes ts node10 types; runtimes that ignore `exports` miss the subpath
- (c) `exports` map plus stub dir — every resolver finds the subpath, and node esm can import it
- (d) stub dir only (`main` + `types`), no `exports` — every cjs resolver finds the subpath; root resolution stays exactly as today

## .taken
(d).

- (a) fails: whodis-client, whodis-react, and whodis-react-storage-browser extend `@tsconfig/node-lts-strictest` (`moduleResolution: "node"`), and ts docs state node10 ignores `exports`
- (c) breaks the root contract: node docs state a set `exports` seals every unlisted subpath, and that pattern targets are a direct string swap with no extension logic. a passthrough `"./dist/*": "./dist/*"` would turn today's live `require('simple-jwt-auth/dist/getUnauthedClaims')` into a not-found. a repair (`"./dist/*.js"` plus a `"./dist/*"` that appends `.js`) leans on key-priority rules i could not confirm, and still seals paths such as `dist/*.d.ts`
- (d) touches no root path. ts docs state directory modules read a nested `package.json` `types`/`main` under node10; node cjs, webpack, metro, and ts node16/bundler (for cjs imports) do the same

## .the cost of (d)
node esm cannot import a directory (`ERR_UNSUPPORTED_DIR_IMPORT`), so a `.mjs` consumer cannot use the subpath (C15). no known consumer is esm; esm consumers keep the root. a later `exports` map is a clean rework, but it must carry the extension rules above.

tsc does not guard this limit: under nodenext, an esm-format `.mts` import of the subpath compiles with no diagnostics, then fails at runtime. the tarball test pins both halves (`[t2]` runtime refusal, `[t7]` clean compile), and the readme warns of it. (c) would close the gap.

## .rework
clean: one stub file plus `files`; a move to (c) later is additive.

## .confidence
80%. doubt: whether a public esm consumer wants the subpath soon.

## .where
`unauthed/package.json`, `package.json` (`files` only)

## .verdict
revised from (c) to (d) on node docs (literal pattern targets, subpath seal); open for wisher review
