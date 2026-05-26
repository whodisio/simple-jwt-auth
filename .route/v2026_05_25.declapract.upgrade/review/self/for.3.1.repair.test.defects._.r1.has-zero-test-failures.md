# self-review: has-zero-test-failures

## verification

ran `THOROUGH=true npm run test` at 2026-05-25 and confirmed zero failures.

## test results

| step | result | details |
|------|--------|---------|
| test:commits | passed | 0 problems, 0 warnings |
| test:types | passed | tsc --noEmit completed |
| test:format:biome | passed | 71 files checked, no fixes |
| test:lint:biome | passed | 71 files checked, no fixes |
| test:lint:cycles | passed | no circular dependencies |
| test:lint:deps | passed | no depcheck issues |
| test:unit | passed | 92 passed, 2 skipped |
| test:integration | passed | 12 passed, 1 skipped |
| test:acceptance:locally | passed | no tests found (expected) |

## total: 104 tests passed, 0 failures

### why 3 tests are skipped

the skipped tests are intentional and documented in code with `.skip`:

1. `createVerifiableSignature.test.ts` line 42: "throw an error" when given wrong key type (TODO)
2. `createVerifiableSignature.test.ts` line 82: "throw an error" when given wrong key type (TODO)
3. `extractPublicKeyFromJwksUri.integration.test.ts`: google jwks test (flaky, network dependent)

these skips existed before the upgrade and are not related to declapract changes.

## why it holds

all test steps completed with exit code 0. no failures detected. the upgrade did not introduce any test regressions.
