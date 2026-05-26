# self-review r2: has-protected-test-intentions

## deeper verification

i verified that the 3 skipped tests existed before the upgrade via `git show origin/main:<file>`.

## verification of skips

### createVerifiableSignature.test.ts lines 42 and 82

checked `git show origin/main:src/signingAlgorithm/createVerifiableSignature.test.ts`:

**original file (origin/main)**:
```ts
when('provided an ecc key', () => {
  // TODO: add additional safety by error if wrong key type given
  then.skip('throw an error', async () => {
```

**current file**:
```ts
when('provided an ecc key', () => {
  // TODO: add additional safety by error if wrong key type given
  then.skip('throw an error', async () => {
```

identical. skip existed before upgrade.

### extractPublicKeyFromJwksUri.integration.test.ts line 7

network-dependent test for google jwks. skipped before the upgrade. i did not modify this file.

## verification method

ran `git show origin/main:<file>` for each file with skips and confirmed:
- line 42 skip: pre-existed
- line 82 skip: pre-existed
- google jwks skip: pre-existed

## why it holds

all 3 skips existed in origin/main before the declapract upgrade. no new skips were introduced. no tests were dropped. no assertions were weakened.

the only changes to test files were:
1. import reorder (biome)
2. import path change (@src alias)
3. import source change (helpful-errors)
4. test asset extraction (to new file)
5. type import syntax (export type)

all are infrastructure changes. zero behavior changes.
