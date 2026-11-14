# split plan — #21 into layer prs

#21 holds 92 files, +6507 lines: too large for one review. the bar is 30 min per pr.
this plan cuts it into 21 layer prs in dependency order, base libs first.
#21 stays open as the index of its layers. it closes unmerged once the last layer merges.

## .the review budget

one layer = at most **250 weighted lines** (30 min at 500 lines/hr, fulcrum F10).

| line kind | weight | why (fulcrum) |
|---|---|---|
| hand-written code, test, doc, record | 1 | read line by line |
| snapshot | 0.5 | read for shape; the test beside it asserts the facts (F11) |
| `pnpm-lock.yaml` | read hunks only | regenerated per layer; a human reads the `importers` specifier lines and `patchedDependencies` (F11) |
| route-engine artifacts (guard, stone, stamp, `passage.jsonl`, flags, `.gitignore`) | 0 | machine output of the route; the reviewer runs the box-local grep below instead (F11) |

counts below are diff lines (adds + dels) at `94fb489`. `L120–158` names a line range of the file at that sha. `~` marks an estimate for a range cut or for new lines.

## .the layers

each layer gets its own branch, `beav/unauthed-<id>-<slug>`. it stacks on the prior layer and retargets to main once that layer merges. each layer is green on `rhx git.release --watch` before the next opens.

### deps + signer

| id | layer | depends on | files (lines) | weighted |
|---|---|---|---|---|
| L1 | deps base: rhachet bumps, keyrack patch, box-local ignores | main | `package.json` rhachet + brains + roles + self-link lines (13) · `pnpm-lock.yaml` (2976, read ~25) · `pnpm-workspace.yaml` (2) · `patches/rhachet-roles-ehmpathy@1.41.0.patch` (16) · `.agent/repo=.this/role=any/skills/set.package.patch.sh` (98) · `.depcheckrc.yml` (5) · `jest.unit.config.ts` (1) · `.route/v2026_11_06.package.install/3.reason.for_rhachet-brains-openrouter.yield.md` (9) | ~169 |
| L2 | signer refuses a key whose type does not fit the alg | L1 | `src/signingAlgorithm/getKeyTypeOfAlg.ts` (11) · `getKeyTypeOfAlg.test.ts` (29) · `createVerifiableSignature.ts` (18) · `createVerifiableSignature.test.ts` (19) · its snap (4) · `createSigningKeyPair.test.ts` (36) · `isSignatureVerified.test.ts` (26) · `readme.md` key-type paragraph (2) | 143 |
| L3 | signer acceptance per alg, and the jwks absent-kid repair | L2 | `src/createSecureDistributedAuthToken.acceptance.test.ts` (110) · its snap (51) · `src/getPublicKey/extractPublicKeyFromJwksUri.integration.test.ts` (54) · its snap (7) | 194 |

### graph walker (test lib)

| id | layer | depends on | files (lines) | weighted |
|---|---|---|---|---|
| W1 | dpdm tree transformers | L3 | new `src/.test/asExternalDepsOfDpdmTree.ts`, cut from `getAllExternalDepsOfEntry.ts` L8–145 (138) · new `asExternalDepsOfDpdmTree.test.ts` (new, ~100) (F12) | ~238 |
| W2 | walker: dpdm call + absent-entry and d.ts cases | W1 | `src/.test/getAllExternalDepsOfEntry.ts` L1–7, L22–25, L146–230 (~96) · `src/.test/getThrownOfCall.ts` (20) · `getAllExternalDepsOfEntry.integration.test.ts` L1–22, L60, L159–217 (~83) · its snap, case2 + case3 half (~15) | ~207 |
| W3 | allowlist assert and the leaky-graph red twin | W2 | `src/.test/assertGraphWithinAllowlist.ts` (43) · `getAllExternalDepsOfEntry.integration.test.ts` L23–58, L61–158 (~134) · its snap, case1 half (~15) | ~185 |

### subpath

| id | layer | depends on | files (lines) | weighted |
|---|---|---|---|---|
| S1 | `simple-jwt-auth/unauthed` entry and its runtime contract | W3 | `src/unauthed.ts` (16) · `unauthed/package.json` (4) · `src/index.ts` (13) · `package.json` `files` line (1) · `src/.test/NAMES_OF_SUBPATH.ts` (11) · `src/unauthed.acceptance.test.ts` L1–94 sans clamp lines (~60), L168–265 (98) · its snap, case2 [t0]–[t2] (~70) | ~238 |
| S2 | subpath refusals of wrong-shape tokens, and the readme | S1 | `src/unauthed.acceptance.test.ts` L266–357 (92) · `readme.md` subpath section (24) · its snap, case2 [t3]–[t4] (~40) | ~136 |
| S3 | clamp: the built subpath graph reaches no signature-side dep | S2 | `src/.test/PACKAGES_OF_SIGNATURE_SIDE.ts` (13) · `src/unauthed.acceptance.test.ts` clamp lines of L1–94 (~34), L95–167 (73) · its snap, case1 (~32) | ~136 |

### tarball acceptance

`src/unauthed.tarball.acceptance.test.ts` (1132) and its snap (148) split by case and `when`. each layer keeps the operations its cases call. the L1–608 header splits across the layers that read it.

| id | layer | depends on | files (lines) | weighted |
|---|---|---|---|---|
| T1a | pack: tarball contents, with the omitted-files red twin (deps `npm`, `tar`) | S3 | `package.json` + `pnpm-lock.yaml` (2, read ~6) · `.route/v2026_11_06.package.install/3.reason.for_npm.yield.md`, `…for_tar.yield.md` (18) · tarball test L1–28, L34–79 (~74) · L102–183 (82) · L259–287 (29) · L1011–1039 (29) · describe frame (~4) · snap (~10) | ~249 |
| T1b | unpack: node requires both entries from the install | T1a | tarball test L80–101 (22) · L184–222 (39) · L288–299 (12) · L475–499 (25) · L595–607 (13) · L620–638 (19) · L640–687 (48) · L1040–1059 (20) · snap (~30) | ~213 |
| T2 | native esm refusal and the browser bundle (dep `esbuild`) | T1b | `package.json` + `pnpm-lock.yaml` (1, read ~3) · `.route/v2026_11_06.package.install/3.reason.for_esbuild.yield.md` (9) · tarball test L29–32 (4) · L426–474 (49) · L579–594 (16) · L689–753 (65) · L755–813 (59) · snap (~40) | ~226 |
| T3 | tsc harness: node16, and the node10 red twin of the omitted files | T2 | tarball test L300–425 (126) · L500–523 (24) · L569–578 (10) · L884–917 (34) · L1060–1078 (19) · snap (~20) | ~223 |
| T4 | tsc node10 wrong use, nodenext esm, bundler | T3 | tarball test L524–568 (45) · L815–882 (68) · L919–972 (54) · L974–1007 (34) · snap (~38) | ~220 |
| T5 | registry install: runtime deps fetched, not linked | T4 | tarball test L223–258 (36) · L1080–1132 (53) | ~89 |

### route records

route records land after the code they record (F13). all paths sit under `.behavior/v2026_11_04.feat-unauthed-subpath/` except `.dream/`.

| id | layer | depends on | files (lines) | weighted |
|---|---|---|---|---|
| R1 | wish and vision | T5 | `0.wish.md` (20) · `1.vision.yield.md` (125) · `1.vision.experience.dimensions.md` (66) | 211 |
| R2 | experience catalog | R1 | `1.vision.experience.case=_.md` (62) · `case=1` … `case=6` (174) | 236 |
| R3 | execution and verification trail | R2 | `1.vision.experience.case=7.redact-is-idempotent.md` (29) · `5.1.execution.from_vision.yield.md` (39) · `5.3.verification.yield.md` (105) · `blocker/1.vision.md` (39) · route-engine artifacts at weight 0: `*.stone` (392), `*.guard` (676), `*.stamp` (203), `.route/passage.jsonl` (323), `.bind/` + `.route/.bind.*` flags (4), `.reviews/peer/.gitignore`, `.route/.gitignore`, `review/self/.gitignore` (11), `refs/template.[feedback].v1.[given].by_human.md` (27) | 212 |
| R4 | fulcrums F1–F9 | R3 | `.fulcrums/inventory.of=fulcrums._.md` rows F1–F9, `case=F1` … `case=F9` (235) | 235 |
| R5 | seeds and dreams | R4 | `.seeds/*` (45) · `.dream/v2026_11_0*.md` (170) · `dreams/*` symlinks (6) | 221 |
| R6 | this split plan and its fulcrums | R5 | `split-plan.md` (106) · `.fulcrums` rows F10–F13 + `case=F10` … `case=F13` (87) | 193 |

## .coverage

every file of #21 lands in exactly one layer, or in named line ranges across layers. none is dropped.

- `package.json`: L1 (rhachet lines) · S1 (`files`) · T1a (`npm`, `tar`) · T2 (`esbuild`)
- `pnpm-lock.yaml`: regenerated in L1, T1a, T2 by `pnpm install`, never hand-cut
- `readme.md`: L2 (key-type paragraph) · S2 (subpath section)
- `.route/v2026_11_06.package.install/*`: each reason rides with its dep (L1, T1a, T2)

## .box-local, kept out of every layer

these live on the box that drove the route. none ships in #21 or in any layer:

- `.agent/keyrack.yml` local edit (org `whodis` → `ehmpathy`, fireworks + xai keys dropped; F5)
- `.gitignore` local un-ignore line
- `.claude/` (settings deletions, local settings, `settings.of.repo.*.bak.json` backups)
- `.agent/.actors/` (the actor's brain dir)
- `.agent/.cache/repo=ehmpathy/role=mechanic/skill=rmsafe/trash/.gitignore` (local deletion)
- `.temp/`, `.log/`
- `.behavior/v2026_11_04.feat-unauthed-subpath/.radio/` (the held record, delivered as ehmpathy/rhachet-roles-ehmpathy#1322)

box-local check, owed on each layer before it opens:

- `git status --short` lists none of the paths above as staged
- the grep below prints naught (an absolute home path is the leak; the dreams name `.agent/.actors/` and `.claude/` as dir names on purpose, so those words alone are no leak)

```sh
git diff --text origin/main HEAD | rhx grepsafe --pattern '/home/[a-z]|/Users/[A-Za-z]'
```

## .the index

the #21 body lists each layer with its id, pr link, and state. it is updated as each layer opens and merges. #21 closes unmerged after R6 merges.
