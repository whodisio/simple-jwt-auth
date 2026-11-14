import { ConstraintError } from 'helpful-errors';

/**
 * .what = the reached deps whose package falls outside an allowlist
 * .why = the clamp's one question
 */
const getDepsOutsideAllowlist = <T extends { dep: string }>(input: {
  deps: T[];
  allowed: string[];
}): T[] => input.deps.filter((reached) => !input.allowed.includes(reached.dep));

/**
 * .what = the clamp's red report: each leaked dep, the chain that reached it, and the fix
 * .why = a red ci run names the file to fix, so no one reads a raw object diff
 */
const asClampReportOfLeaks = (input: {
  leaks: { dep: string; chain: string[] }[];
}): string =>
  [
    'simple-jwt-auth/unauthed reaches a forbidden dep',
    ...input.leaks.flatMap((leak) => [
      `   ├─ dep: ${leak.dep}`,
      '   │  └─ via',
      ...leak.chain.map(
        (hop, index) =>
          `   │     ${index === leak.chain.length - 1 ? '└─' : '├─'} ${hop}`,
      ),
    ]),
    '   └─ fix: cut the hop that crossed sides; an op that needs this dep belongs to the root entry (allowlist: DEPS_ALLOWED in src/unauthed.acceptance.test.ts)',
  ].join('\n');

/**
 * .what = the clamp: fails loud if a walk reaches a dep outside the allowlist
 * .why = the subpath's lean graph is its whole reason to exist; a leak must turn ci red, with the fix named
 */
export const assertGraphWithinAllowlist = (input: {
  deps: { dep: string; chain: string[] }[];
  allowed: string[];
}): void => {
  const leaks = getDepsOutsideAllowlist(input);
  if (leaks.length > 0)
    throw new ConstraintError(asClampReportOfLeaks({ leaks }));
};
