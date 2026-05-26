# self-review r4: has-complete-defect-entries

## review process

this round found substantive issues in the inventory.

the initial review checked whether each defect had what/how/why/fix fields.
deeper review checked whether "how" correctly documented the diff against origin/main.

three issues were found and corrected in the inventory.

## defect-by-defect analysis

### defects 1-4: return type annotations

after fixes:
- **what**: biome lint error `noImplicitFunctionReturnType` — describes the error
- **how**: biome.jsonc added (new file in diff) with the rule — documents the diff
- **why**: origin/main had no biome.jsonc; declapract added it — explains root cause
- **fix**: added return type annotations with diffs — shows the solution

all four fields present and now reference the diff.

### defect 5: type re-export

- **what**: stated "typescript `isolatedModules` error on type re-exports" — describes the error
- **how**: originally stated "biome enforces stricter module isolation" — **this was incorrect**
  - **issue found**: the actual change was in tsconfig.json, not biome
  - **fix applied**: corrected to "tsconfig.json changed to extend `@tsconfig/strictest` which has `isolatedModules: true`"
- **why**: stated "`export { Type }` is ambiguous when `isolatedModules` is enabled" — explains the cause
- **fix**: stated "changed to `export type { Type }` syntax" with diff — shows the solution

all four fields present after correction.

### defects 6-7: test file exports

after fixes:
- **what**: biome lint error `noExportsInTest` — describes the error
- **how**: biome.jsonc added (new file in diff) with `noExportsInTest` rule — documents the diff
- **why**: origin/main had no biome.jsonc; declapract added it — explains root cause
- **fix**: moved shared test assets to `src/__test_assets__/exampleKeyPairs.ts` — shows the solution

all four fields present and now reference the diff.

### defect 8: dpdm cycle detection

after fixes:
- **what**: dpdm found cycles in node_modules — describes the error
- **how**: diff shows pattern present in origin/main (pre-existent issue) — documents the diff
- **why**: pattern syntax issue — regex vs glob — explains root cause
- **fix**: changed exclude pattern without regex anchor — shows the solution

all four fields present and now clarify this was pre-existent.

## issues found and fixed

### issue 1: defect 5's "how" was inaccurate
- **before**: "biome enforces stricter module isolation"
- **after**: "tsconfig.json changed to extend `@tsconfig/strictest` which has `isolatedModules: true`"
- **lesson**: verify actual source of rule, not just which tool reports it

### issue 2: defects 1-4 and 6-7 "how" fields lacked diff reference
- **before**: described what the rule requires (e.g., "biome 2.3.8 requires explicit return types")
- **after**: documented the diff change (e.g., "biome.jsonc added (new file in diff)")
- **lesson**: "how" should answer "what changed in the diff?" not "what does the rule do?"

### issue 3: defect 8's "how" did not mention origin/main comparison
- **before**: "dpdm exclude pattern did not match correctly"
- **after**: "diff shows `--exclude '^node_modules'` present in origin/main (pre-existent issue)"
- **lesson**: diff comparison reveals pre-existent vs upgrade-introduced issues

## why it now holds

after the correction, all defect entries (1-8) have accurate four-field entries:
1. what — the defect is described
2. how — what changed (now correctly identifies the source)
3. why — root cause is documented
4. fix — resolution is shown with diffs

the inventory is now complete and accurate.
