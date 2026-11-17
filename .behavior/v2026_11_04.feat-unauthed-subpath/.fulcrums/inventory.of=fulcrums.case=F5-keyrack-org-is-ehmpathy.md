# F5 — this repo's keyrack org is `ehmpathy`, not `whodis`

## .the fork
- (a) `org: ehmpathy` — every bare key slugs under `ehmpathy`; the review brain's `OPENROUTER_API_KEY` reads `ehmpathy.prep.OPENROUTER_API_KEY`, which the ehmpath keyrack holds
- (b) `org: [whodis, ehmpathy]` — `whodis` stays default; `ehmpathy` becomes an allowlisted member. the brain's creds pass no org, so it still slugs under `whodis` and still misses
- (c) `org: [ehmpathy, whodis]` — same reach as (a), plus a `whodis` member that holds no key today
- (d) keep `org: whodis` and fill `whodis.prep.OPENROUTER_API_KEY` — refused by the director: no `whodis.prep` key will be filled

## .taken
(a). evidence:
- `CREDS_OF_REVIEW_BRAIN.js` (rhachet-roles-bhrain 0.42.4) passes `keyrack: { owner: 'ehmpath', env: 'prep' }`, no org
- `getOneKeyrackGrantByKey.js` (rhachet 1.51.0): a bare key "slugs under the asked member; absent, under the default org"; `loadManifestExplicit.js`: the default org is `orgs[0]`
- `rhx keyrack list --owner ehmpath` holds `ehmpathy.prep.OPENROUTER_API_KEY`; it holds no `whodis.*` key at all
- so the only spec under which the brain finds the held key puts `ehmpathy` first. (c) adds a member that names no key; (a) is the smaller spec

the keyrack org names whose keys this repo's robots use, not who owns the package. the npm and github owner stays `whodis`.

## .rework
clean: one line in `.agent/keyrack.yml`.

## .confidence
85%. doubt: whether `rhachet init --keys` (run by `npm run prepare` outside ci) rewrites `org` from the git remote on a later prepare. checked at execution: the file is tracked; a rewrite would show in the diff.

## .where
`.agent/keyrack.yml`

## .verdict
best-guessed on the director's direction; open for review
