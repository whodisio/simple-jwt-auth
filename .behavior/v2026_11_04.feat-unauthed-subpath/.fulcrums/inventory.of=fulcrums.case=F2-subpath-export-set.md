# F2 — subpath export set

## .the fork
- (a) exactly the five names the wish lists: `getUnauthedClaims`, `getUnauthedHeaderClaims`, `redactSignature`, `isJSONWebToken`, `SimpleJwtAuthError`, plus types `MinimalTokenClaims`, `MinimalTokenHeaderClaims`
- (b) (a), plus `isExpiredToken` and `isRedactedSignatureToken`

## .taken
(a). the target libs call only `getUnauthedClaims` and `redactSignature` (whodis-client: `src/isTokenExpired.ts`, `src/isTokenRefreshable.ts`, `src/environment/assertTokenLooksUsableForTargetEnv.ts`; whodis-react: `src/logic/claims/getAuthableTokenClaims.ts`; whodis-react-storage-browser: `src/logic/storage/setTokenToStorage.ts`, `src/logic/synchronization/isTokenSynchronized.ts`). whodis-client keeps its own `isTokenExpired`, so (b)'s premise has no consumer. the types erase at emit and name the generic bound of each decode op, so they ride along at zero cost.

## .rework
clean: one export line each, if a consumer asks later.

## .confidence
95%. matches the wish's list and the observed call sites.

## .where
`src/unauthed.ts`

## .verdict
revised from (b) to (a) on consumer evidence; open for wisher review
