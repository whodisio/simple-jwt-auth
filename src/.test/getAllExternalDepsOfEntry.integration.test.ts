import { genTempDir, given, then, useBeforeAll, when } from 'test-fns';

import { writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { assertGraphWithinAllowlist } from './assertGraphWithinAllowlist';
import { getAllExternalDepsOfEntry } from './getAllExternalDepsOfEntry';
import { getThrownOfCall } from './getThrownOfCall';

/**
 * .what = the allowlist the fixture graph is graded against, same as the subpath's
 */
const DEPS_ALLOWED = ['buffer'];

/**
 * .what = a chain with each file hop cut to its basename, and the final request kept whole
 * .why = the fixture's temp dir differs per run; the request is a package name, not a path
 */
const asChainOfFileBasenames = (input: { chain: string[] }): string[] => [
  ...input.chain.slice(0, -1).map((hop) => basename(hop)),
  ...input.chain.slice(-1),
];

/**
 * .what = a decode-side graph that leaks a top-level, a scoped, a lazy, and a dynamic dep
 * .why = the clamp's red twin: the walk that passes dist/unauthed.js must fail this
 */
const genClampFixtureOfLeakyGraph = (input: {
  slug: string;
}): { entry: string; dir: string } => {
  const dir = genTempDir({ slug: input.slug });
  writeFileSync(
    join(dir, 'entry.js'),
    "exports.getClaims = require('./claims').getClaims;\n",
  );
  writeFileSync(
    join(dir, 'claims.js'),
    [
      "const { parseDomain } = require('parse-domain');",
      "const { UnexpectedCodePathError } = require('@ehmpathy/error-fns/dist/index');",
      "const { decode } = require('./decode');",
      'exports.getClaims = (token) => ({ claims: decode(token), parseDomain });',
      '',
    ].join('\n'),
  );
  writeFileSync(
    join(dir, 'decode.js'),
    [
      "const { Buffer } = require('buffer');",
      'exports.decode = (value) => {',
      "  const crypto = require('node:crypto');",
      "  return Buffer.from(value, 'base64').toString() + crypto.randomUUID();",
      '};',
      "exports.loadLater = () => import('axios');",
      '',
    ].join('\n'),
  );
  return { entry: join(dir, 'entry.js'), dir };
};

describe('getAllExternalDepsOfEntry', () => {
  given(
    '[case1] decode-side files gain a top-level, a scoped, a lazy, and a dynamic forbidden request',
    () => {
      const fixture = useBeforeAll(async () =>
        genClampFixtureOfLeakyGraph({ slug: 'unauthed-clamp-redcase' }),
      );

      when('[t0] its static require graph is walked', () => {
        const walk = useBeforeAll(async () => ({
          deps: getAllExternalDepsOfEntry({
            entry: fixture.entry,
            extensions: null,
          }),
        }));

        then(
          'it reports each external dep, the allowlisted one included',
          () => {
            expect(walk.deps.map((reached) => reached.dep).sort()).toEqual([
              '@ehmpathy/error-fns',
              'axios',
              'buffer',
              'crypto',
              'parse-domain',
            ]);
          },
        );

        then(
          'it names a scoped dep by its scope and name, not its subpath',
          () => {
            const reached = walk.deps.find(
              (dep) => dep.request === '@ehmpathy/error-fns/dist/index',
            );
            expect(reached?.dep).toEqual('@ehmpathy/error-fns');
          },
        );

        then('it names the chain to the top-level require', () => {
          const reached = walk.deps.find((dep) => dep.dep === 'parse-domain');
          expect(reached?.chain.map((hop) => basename(hop))).toEqual([
            'entry.js',
            'claims.js',
            'parse-domain',
          ]);
        });

        then(
          'it sees the require nested in a function body, and names its chain',
          () => {
            const reached = walk.deps.find((dep) => dep.dep === 'crypto');
            expect(reached?.request).toEqual('node:crypto');
            expect(reached?.chain.map((hop) => basename(hop))).toEqual([
              'entry.js',
              'claims.js',
              'decode.js',
              'node:crypto',
            ]);
          },
        );

        then('it sees a dynamic import, as a bundler would', () => {
          const reached = walk.deps.find((dep) => dep.dep === 'axios');
          expect(reached?.chain.map((hop) => basename(hop))).toEqual([
            'entry.js',
            'claims.js',
            'decode.js',
            'axios',
          ]);
        });

        then(
          'the clamp fails loud, and names each dep, its chain, and the fix',
          () => {
            const thrown = getThrownOfCall({
              call: () =>
                assertGraphWithinAllowlist({
                  deps: walk.deps.map((reached) => ({
                    ...reached,
                    chain: asChainOfFileBasenames({ chain: reached.chain }),
                  })),
                  allowed: DEPS_ALLOWED,
                }),
            });
            expect(thrown.name).toEqual('ConstraintError');
            expect(thrown.message).toContain('dep: parse-domain');
            expect(thrown.message).not.toContain('dep: buffer');
            expect(thrown.message).toContain(
              '└─ @ehmpathy/error-fns/dist/index',
            );
            expect(thrown.message).toContain('fix:');
            expect(thrown.message).toMatchSnapshot();
          },
        );
      });
    },
  );

  given(
    '[case3] a decode-side d.ts gains an import type of a signature-side package',
    () => {
      const fixture = useBeforeAll(async () => {
        const dir = genTempDir({ slug: 'unauthed-clamp-redcase-dts' });
        writeFileSync(
          join(dir, 'entry.d.ts'),
          "export type { Claims } from './claims';\n",
        );
        writeFileSync(
          join(dir, 'claims.d.ts'),
          [
            "import type { AxiosInstance } from 'axios';",
            'export type Claims = { client: AxiosInstance };',
            '',
          ].join('\n'),
        );
        return { entry: join(dir, 'entry.d.ts') };
      });

      when('[t0] its d.ts graph is walked', () => {
        then(
          'it reports the type-only dep, so the d.ts walk of the subpath can fail',
          () => {
            const deps = getAllExternalDepsOfEntry({
              entry: fixture.entry,
              extensions: ['.d.ts'],
            });
            expect(deps.map((reached) => reached.dep)).toEqual(['axios']);
            expect(
              deps[0]?.chain.map((hop) => basename(hop)),
            ).toEqual(['entry.d.ts', 'claims.d.ts', 'axios']);
          },
        );
      });
    },
  );

  given('[case2] a walk asked for an entry that does not exist', () => {
    when('[t0] the walk runs', () => {
      then('it fails loud, rather than report a clean graph', () => {
        const thrown = getThrownOfCall({
          call: () =>
            getAllExternalDepsOfEntry({
              entry: join(__dirname, '..', '..', 'dist', 'absent.js'),
              extensions: null,
            }),
        });
        expect(thrown.name).toEqual('MalfunctionError');
        expect(thrown.message).toMatch(/dpdm/);
        expect(thrown.message).toContain('hint');

        // snap the header a reader meets; the body below it holds a temp path and dpdm's stack, which vary per run
        const [header] = thrown.message.split('\n');
        expect(header).toMatchSnapshot();
      });
    });
  });
});
