# self-review: has-compared-against-main

## verification

for each defect, i asked "what changed?" and compared against origin/main.

## defect analysis

### defects 1-4: absent return types

**what changed?** biome.jsonc was added by declapract with `noImplicitFunctionReturnType` rule enabled.

**diff command**: `git diff origin/main -- biome.jsonc` (new file)

**root cause**: origin/main had no biome.jsonc. declapract upgrade added biome 2.3.8 with stricter lint rules. the rule `noImplicitFunctionReturnType` requires explicit return types on exported functions.

### defect 5: type re-export

**what changed?** tsconfig.json now has `isolatedModules: true`.

**diff command**: `git diff origin/main -- tsconfig.json`

**root cause**: origin/main did not enforce isolated modules. declapract upgrade enabled the rule, which requires `export type` for type-only re-exports.

### defects 6-7: exports from test files

**what changed?** biome.jsonc was added with `noExportsInTest` rule enabled.

**diff command**: `git diff origin/main -- biome.jsonc` (new file)

**root cause**: origin/main had no lint rule against test exports. biome 2.3.8 forbids exports from test files to prevent production imports.

### defect 8: dpdm cycle detection

**what changed?** package.json test:lint:cycles command used `--exclude '^node_modules'`.

**diff command**: `git diff origin/main -- package.json`

**root cause**: the `'^node_modules'` pattern is regex but dpdm expected glob. origin/main had same issue but declapract did not fix it.

## why it holds

each defect was traced to a specific change in the upgrade:
- defects 1-4, 6-7: biome.jsonc added → new lint rules
- defect 5: tsconfig.json changed → isolatedModules enabled
- defect 8: package.json command → pre-existed, needed manual fix

all root causes were identified via diff against origin/main.
