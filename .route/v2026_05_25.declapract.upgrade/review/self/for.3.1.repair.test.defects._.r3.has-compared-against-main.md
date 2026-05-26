# self-review r3: has-compared-against-main

## deeper verification

i ran the actual git diff commands and verified the root causes.

## evidence

### defects 1-4, 6-7: biome.jsonc rules

```sh
git diff origin/main -- biome.jsonc
```

result: new file. biome.jsonc did not exist in origin/main.

key rules that caused defects:
- `noImplicitFunctionReturnType` → defects 1-4 (return type annotations)
- `noExportsInTest` → defects 6-7 (test file exports)

### defect 5: isolatedModules

```sh
git diff origin/main -- tsconfig.json
```

result: extends changed from `@tsconfig/node-lts-strictest` to `@tsconfig/strictest`.

verified via:
```sh
cat node_modules/@tsconfig/strictest/tsconfig.json
```

confirmed `isolatedModules: true` in the strictest config.

### defect 8: dpdm pattern

```sh
git diff origin/main -- package.json
```

result: `--exclude '^node_modules'` was present in origin/main too.
this was a pre-existent issue, not introduced by the upgrade.
i fixed it by removing the regex anchor.

## why it holds

each defect has verified diff evidence:
- defects 1-4, 6-7: biome.jsonc new file with stricter rules
- defect 5: tsconfig.json switched to strictest → isolatedModules enabled
- defect 8: package.json had pre-existent pattern issue

all root causes confirmed via git diff against origin/main.
