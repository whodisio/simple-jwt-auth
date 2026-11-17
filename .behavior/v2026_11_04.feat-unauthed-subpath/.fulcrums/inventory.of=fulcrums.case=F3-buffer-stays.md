# F3 — `buffer` stays in the subpath graph

## .the fork
- (a) keep `base64UrlDecode` on the `buffer` package (commit 6974696 chose it for cross-platform compat)
- (b) swap to `atob` + `TextDecoder` in the decode path, drop `buffer` from the subpath graph

## .taken
(a). `buffer` is not on the wish's forbidden list, weighs 58kb raw source (far less once minified + gzipped), and (b) would change decode behavior on react-native and node 8 (`engines`), where `atob`/`TextDecoder` may lack.

## .rework
clean: one file, and the clamp list gains `buffer`.

## .confidence
85%.

## .where
`src/base64Url/base64UrlDecode.ts`

## .verdict
open
