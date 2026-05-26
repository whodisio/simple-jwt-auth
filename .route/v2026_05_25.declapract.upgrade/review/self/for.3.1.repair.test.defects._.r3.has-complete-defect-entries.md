# self-review r3: has-complete-defect-entries

## verification

i reviewed each defect entry in 3.1.repair.test.defects.v1.i1.md.

## checklist

| defect | what | how | why | fix |
|--------|------|-----|-----|-----|
| 1 | biome lint error `noImplicitFunctionReturnType` | biome 2.3.8 requires explicit return types | prior eslint did not enforce | added `: string` |
| 2 | biome lint error `noImplicitFunctionReturnType` | biome 2.3.8 requires explicit return types | prior eslint did not enforce | added `: boolean` |
| 3 | biome lint error `noImplicitFunctionReturnType` | biome 2.3.8 requires explicit return types | prior eslint did not enforce | added `: void` |
| 4 | biome lint error `noImplicitFunctionReturnType` (3 funcs) | biome 2.3.8 requires explicit return types | prior eslint did not enforce | added return types to all three |
| 5 | typescript `isolatedModules` error | stricter module isolation | `export { Type }` ambiguous | changed to `export type` |
| 6-7 | biome lint error `noExportsInTest` | biome forbids test exports | prevent production imports | moved to `__test_assets__` |
| 8 | dpdm found cycles in node_modules | exclude pattern did not match | regex vs glob syntax | removed regex anchor |

## why it holds

all 8 defects have complete entries with:
- what: the defect is described
- how: what changed (biome rules, tsconfig, pattern syntax)
- why: root cause (prior config did not enforce, syntax mismatch)
- fix: resolution with diff examples

the inventory follows the required format.
