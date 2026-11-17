# F9 — prior root behaviors and snapshot taste stay as they are in this pr

## .the fork
- (a) take each late nitpick that asks for a root behavior change or a snapshot reshape: wrap the raw node error of an unparseable pem, check the ec curve, collapse the error snaps into one string per token, decode the redacted token in its snap, rename `ec` to `ecc` in messages, regenerate the fixed rsa key at 2048 bits
- (b) keep them out: each is either a root behavior main already has (not a regression), or a reshape of a snap whose content is already complete and correct

## .taken
(b), with a record per item:

- unparseable pem → raw node error: main threw a raw error there too; a wrap changes the root's thrown class (same reason as F8)
- curve not checked: main signed it too; the fix rides with the verify-side guard in dream `v2026_11_06.repair.signature-key-type-guard`, catalog cell C31
- error snaps keyed `{ message, name }` per token: jest sorts the keys; the content is whole and each token is named in its entry. a reshape is taste and churns every entry
- redacted token snap is base64: the redacted string is the op's output, the contract itself; the signed-token snap has a decoded twin
- `'ec'` in messages: it is node's own `asymmetricKeyType` name, the value a caller sees in `createPrivateKey(key).asymmetricKeyType`; the `ecc` in test titles predates this pr
- the fixed rsa public key in `isSignatureVerified.test.ts` is 4096-bit: the signer's fixture pair `exampleRsaKeyPair` is 4096-bit too, so the wrong key is the same size; the test now asserts the two modulus lengths match
- the jwks integration test, once skipped, now runs live, with a new `unlisted` kid case: outside the wish, on record as catalog cells C32/C33 (D11). its error message is main's, snapped as is; a message that names the kid and uri is a root change held out
- the one-line diagnostics snap inside `{ diagnostics: [...] }`, the esm error inside `{ lineOfError }`, the 9 equal `{ message, name }` blocks of the absent-token case: each shape is what the test reads and asserts; a reshape is taste that churns entries and adds no fact

## .rework
clean: each is a local change in one test or one guard, none built upon.

## .confidence
90%. doubt: the commander may want the pem wrap with the guard, as one release note.

## .where
`src/unauthed.acceptance.test.ts`, `src/createSecureDistributedAuthToken.acceptance.test.ts`, `src/signingAlgorithm/*.test.ts`, `src/signingAlgorithm/createVerifiableSignature.ts`, `src/getPublicKey/extractPublicKeyFromJwksUri.integration.test.ts`, `src/unauthed.tarball.acceptance.test.ts`

## .verdict
best-guessed; open for commander review in the pr body
