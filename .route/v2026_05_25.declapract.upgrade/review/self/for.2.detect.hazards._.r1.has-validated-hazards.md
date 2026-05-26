# self-review: has-validated-hazards

## validation of identified hazards

### hazard 1: cicd hazard: package manager switch (CRITICAL)

**verdict**: VALID — actual issue

**proof**: the CI workflow `.github/workflows/.test.yml` was updated by declapract to use pnpm. the workflow now uses:
- `corepack enable` to enable pnpm
- `pnpm install --frozen-lockfile` instead of `npm ci`
- proper pnpm cache setup

this hazard correctly predicted a required change.

### hazard 2: test hazard: declapract major version bump

**verdict**: VALID — actual issue

**proof**: the declapract upgrade introduced biome 2.3.8 with stricter lint rules that caused 8 failures:
- explicit return types required on all exported functions
- `isolatedModules` requires `export type` for re-exported types
- `noExportsInTest` forbids exports from test files

all failures were real and required code changes to fix.

### hazard 3: config hazard: new rhachet dependencies

**verdict**: VALID — low impact, actual dependency

**proof**: rhachet dependencies were added and work correctly. no production impact since these are devDependencies.

## conclusion

all three hazards identified in `2.detect.hazards.v1.i1.md` were valid issues that required remediation. no false positives detected.

test suite passes after all fixes applied:
- 94 unit tests passed
- 13 integration tests passed
- 0 acceptance tests (none defined)
