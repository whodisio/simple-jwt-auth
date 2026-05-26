# self-review r2: has-validated-hazards

## deeper validation

i re-read the hazard document line by line and compared against the actual changes.

### hazard 1: cicd hazard: package manager switch

**claim in hazard doc**: `.github/workflows/.test.yml` line 36 uses `npm ci --ignore-scripts`

**what i found**: the hazard document was based on old file structure. declapract refactored the workflows:
- install step moved to `.github/workflows/.install.yml`
- `.install.yml` now uses `pnpm/action-setup@v4` (line 45)
- `.install.yml` now uses `pnpm install --frozen-lockfile` (line 49)
- cache key changed from npm to pnpm hash (line 25: `md5sum pnpm-lock.yaml`)

**verdict**: VALID hazard. the prediction was correct (CI would break without pnpm migration), but the implementation differs from what the hazard doc described. declapract applied the fix automatically by restructured workflows.

### hazard 2: test hazard: declapract major version bump

**claim in hazard doc**: major version bumps may change generated code patterns

**what i found**: the actual breakage was not in generated code patterns, but in stricter biome lint rules:
- biome 2.3.8 requires explicit return types (`noImplicitFunctionReturnType`)
- biome 2.3.8 enforces `export type` for type re-exports (`isolatedModules`)
- biome 2.3.8 forbids exports from test files (`noExportsInTest`)

these are lint rules, not generated code. the hazard category was correct (tests would break) but the mechanism differed.

**verdict**: VALID hazard, different manifestation. 8 lint failures required manual fixes.

### hazard 3: config hazard: new rhachet dependencies

**claim in hazard doc**: may require roles to be linked before agent skills work

**what i found**: the actual issue was depcheck flagged rhachet packages as unused, not role link issues. fixed by:
- added rhachet packages to `.depcheckrc.yml` ignores
- also added other packages flagged by depcheck: `@ehmpathy/error-fns`, `type-fns`, etc.

**verdict**: VALID hazard, different manifestation. depcheck failed, not role link.

## what i missed in r1

in r1, i validated that hazards were real but did not verify the specific claims in the hazard document. on closer inspection:
- hazard 1 cited wrong file/line (old workflow structure)
- hazard 2 cited wrong mechanism (generated code vs lint rules)
- hazard 3 cited wrong failure mode (role link vs depcheck)

all three hazards were real, but the hazard document was imprecise about details.

## conclusion

all hazards were valid predictions of breakage.
the hazard document was accurate in category but imprecise in details.
no false positives. test suite passes.
