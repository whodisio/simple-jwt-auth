import { given, then, useBeforeAll, when } from 'test-fns';

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { assertGraphWithinAllowlist } from './.test/assertGraphWithinAllowlist';
import { getAllExternalDepsOfEntry } from './.test/getAllExternalDepsOfEntry';
import { getThrownOfCall } from './.test/getThrownOfCall';
import { NAMES_OF_SUBPATH } from './.test/NAMES_OF_SUBPATH';
import { PACKAGES_OF_SIGNATURE_SIDE } from './.test/PACKAGES_OF_SIGNATURE_SIDE';
import { base64UrlEncode } from './base64Url/base64UrlEncode';

/**
 * .what = the deps the decode-side graph may reach
 * .why = `buffer` serves base64 decode in every runtime; aught else is a leak
 */
const DEPS_ALLOWED = ['buffer'];

/**
 * .what = the deps the wish names: the signature side of the package
 * .why = named apart from the allowlist so a red run reads in the wish's words
 */
const DEPS_FORBIDDEN: string[] = [...PACKAGES_OF_SIGNATURE_SIDE, 'crypto'];

/**
 * .what = every name the root exported before the subpath existed
 * .why = the wish holds the root to its contract; a lost or renamed export fails here
 */
const NAMES_OF_ROOT_PRIOR = [
  'DiscoverJwksUriFromAuthServerMetadataError',
  'ExtractPublicKeyFromJwksUriError',
  'GetPublicKeyOfTokenError',
  'JwtVerificationError',
  'PotentialCSRFAttackError',
  'PotentialCSRFVulnerabilityError',
  'PotentialXSSVulnerabilityError',
  'SimpleJwtAuthError',
  'createSecureDistributedAuthToken',
  'createSigningKeyPair',
  'getAuthedClaims',
  'getPublicKey',
  'getSignedClaims',
  'getTokenFromAuthorizationCookie',
  'getTokenFromHeaders',
  'getUnauthedClaims',
  'getUnauthedHeaderClaims',
  'isExpiredToken',
  'isJSONWebToken',
  'isRedactedSignatureToken',
  'isSameSite',
  'redactSignature',
];

/**
 * .what = a token in the shape the decode ops expect
 * .why = claims set here are the claims each decode assertion reads back
 */
const genTokenFixture = (input: { signature: string }): string => {
  const asSegment = (value: object) => base64UrlEncode(JSON.stringify(value));
  const header = asSegment({ alg: 'RS256', typ: 'JWT' });
  const body = asSegment({
    iss: 'https://auth.example.com',
    aud: 'b2f2e7a0-0000-4000-8000-000000000000',
    sub: 'c3a3f8b1-0000-4000-8000-000000000000',
    exp: 1893456000,
  });
  return [header, body, input.signature].join('.');
};

/**
 * .what = the reached deps whose package is on a named list
 * .why = lets a red run report in the wish's own words
 */
const getDepsOnList = <T extends { dep: string }>(input: {
  deps: T[];
  names: string[];
}): T[] => input.deps.filter((reached) => input.names.includes(reached.dep));

/**
 * .what = the files a consumer's lookup of `simple-jwt-auth/unauthed` lands on: its js and its types
 * .why = the clamp walks what the contract hands a consumer, found the way the consumer finds it
 */
const getEntriesOfSubpath = (): { js: string; types: string } => {
  const pathOfStub = require.resolve('simple-jwt-auth/unauthed/package.json');
  const stub = JSON.parse(readFileSync(pathOfStub, 'utf8')) as {
    types: string;
  }; // .note = the stub is this package's own json; `types` is its declared field
  return {
    js: require.resolve('simple-jwt-auth/unauthed'),
    types: join(dirname(pathOfStub), stub.types),
  };
};

// .note = the clamp's red twin (a leaky graph it must fail, and an absent entry it must not pass) lives in src/.test/getAllExternalDepsOfEntry.integration.test.ts
describe('unauthed', () => {
  given(
    '[case1] the built subpath entry, as `simple-jwt-auth/unauthed` finds it',
    () => {
      const entries = useBeforeAll(async () => getEntriesOfSubpath());

      when('[t0] its static require graph is walked', () => {
        const walk = useBeforeAll(async () => ({
          deps: getAllExternalDepsOfEntry({
            entry: entries.js,
            extensions: null,
          }),
        }));

        then(
          'the walk starts where the lookup lands: the built dist/unauthed.js',
          () => {
            expect(entries.js).toEqual(
              join(__dirname, '..', 'dist', 'unauthed.js'),
            );
          },
        );

        then('the clamp passes: no dep outside the allowlist', () => {
          // called bare, so a real leak fails with the clamp's own report, not an object diff
          assertGraphWithinAllowlist({
            deps: walk.deps,
            allowed: DEPS_ALLOWED,
          });
        });

        then(
          'it reaches none of the signature-side deps the wish names',
          () => {
            expect(
              getDepsOnList({ deps: walk.deps, names: DEPS_FORBIDDEN }),
            ).toEqual([]);
          },
        );

        then('it reaches buffer, via base64 decode only', () => {
          expect(walk.deps.map((reached) => reached.dep)).toEqual(['buffer']);
          expect(walk.deps).toMatchSnapshot();
        });
      });

      when(
        '[t1] its declaration graph, from the stub `types` field, is walked',
        () => {
          const walk = useBeforeAll(async () => ({
            deps: getAllExternalDepsOfEntry({
              entry: entries.types,
              extensions: ['.d.ts'],
            }),
          }));

          then('the walk starts at the built dist/unauthed.d.ts', () => {
            expect(entries.types).toEqual(
              join(__dirname, '..', 'dist', 'unauthed.d.ts'),
            );
          });

          // .note = dpdm sees import and export declarations, import() calls, and require(); not inline `import("pkg").T` type nodes
          then(
            'the published types import or re-export no external package',
            () => {
              expect(walk.deps).toEqual([]);
            },
          );
        },
      );
    },
  );

  given('[case2] a consumer requires simple-jwt-auth/unauthed', () => {
    when('[t0] the subpath and the root are both loaded', () => {
      const loaded = useBeforeAll(async () => ({
        unauthed: require('simple-jwt-auth/unauthed'),
        root: require('simple-jwt-auth'),
      }));

      then('the subpath exposes the five decode-side names', () => {
        expect(Object.keys(loaded.unauthed).sort()).toEqual(
          [...NAMES_OF_SUBPATH].sort(),
        );
        expect(Object.keys(loaded.unauthed).sort()).toMatchSnapshot();
      });

      then('the subpath exposes no verify op', () => {
        expect(loaded.unauthed.getAuthedClaims).toBeUndefined();
        expect(loaded.unauthed.getSignedClaims).toBeUndefined();
      });

      then('both entries share one SimpleJwtAuthError class', () => {
        expect(loaded.unauthed.SimpleJwtAuthError).toBe(
          loaded.root.SimpleJwtAuthError,
        );
      });

      then('the root holds the same object for each subpath name', () => {
        // a local root export that shadows the `export *` would fail here
        for (const name of NAMES_OF_SUBPATH)
          expect(loaded.root[name]).toBe(loaded.unauthed[name]);
      });

      then('the root keeps its verify ops', () => {
        expect(typeof loaded.root.getAuthedClaims).toBe('function');
        expect(typeof loaded.root.getSignedClaims).toBe('function');
      });

      then('the root still exports every prior name', () => {
        expect(Object.keys(loaded.root)).toEqual(
          expect.arrayContaining(NAMES_OF_ROOT_PRIOR),
        );
        expect(Object.keys(loaded.root).sort()).toMatchSnapshot();
      });
    });

    when('[t1] a wellformed token is decoded', () => {
      then('it returns the body and header claims', () => {
        const unauthed = require('simple-jwt-auth/unauthed');
        const token = genTokenFixture({ signature: 'c2lnbmF0dXJl' });
        expect(unauthed.getUnauthedClaims({ token }).iss).toEqual(
          'https://auth.example.com',
        );
        expect(unauthed.getUnauthedHeaderClaims({ token }).alg).toEqual(
          'RS256',
        );
        expect(unauthed.isJSONWebToken(token)).toBe(true);
        expect({
          claims: unauthed.getUnauthedClaims({ token }),
          header: unauthed.getUnauthedHeaderClaims({ token }),
          isJSONWebToken: unauthed.isJSONWebToken(token),
        }).toMatchSnapshot();
      });
    });

    when('[t2] a token is redacted twice', () => {
      then('the second redact returns the first result unchanged', () => {
        const unauthed = require('simple-jwt-auth/unauthed');
        const token = genTokenFixture({ signature: 'c2lnbmF0dXJl' });
        const redacted = unauthed.redactSignature({ token });
        expect(redacted.split('.')[2]).toEqual('__REDACTED__');
        expect(unauthed.redactSignature({ token: redacted })).toEqual(redacted);
        expect(redacted).toMatchSnapshot();
      });

      then('the redacted token still decodes to the same claims', () => {
        const unauthed = require('simple-jwt-auth/unauthed');
        const token = genTokenFixture({ signature: 'c2lnbmF0dXJl' });
        const redacted = unauthed.redactSignature({ token });
        expect(unauthed.isJSONWebToken(redacted)).toBe(true);
        expect(unauthed.getUnauthedClaims({ token: redacted })).toEqual(
          unauthed.getUnauthedClaims({ token }),
        );
        expect(unauthed.getUnauthedHeaderClaims({ token: redacted })).toEqual(
          unauthed.getUnauthedHeaderClaims({ token }),
        );
      });

      then('the root reads it as a redacted token', () => {
        const unauthed = require('simple-jwt-auth/unauthed');
        const root = require('simple-jwt-auth');
        const token = genTokenFixture({ signature: 'c2lnbmF0dXJl' });
        expect(root.isRedactedSignatureToken(token)).toBe(false);
        expect(
          root.isRedactedSignatureToken(unauthed.redactSignature({ token })),
        ).toBe(true);
      });
    });

    // .note = a jwt-shaped token whose parts do not parse ('a.b.c') throws a raw SyntaxError; see .dream/v2026_11_06.repair.decode-ops-throw-raw-syntaxerror.md
    when('[t3] a wrong-shape or absent token is decoded', () => {
      then('each value op throws the shared SimpleJwtAuthError', () => {
        const unauthed = require('simple-jwt-auth/unauthed');
        for (const token of ['not-a-jwt', '', undefined]) {
          expect(() => unauthed.getUnauthedClaims({ token })).toThrow(
            unauthed.SimpleJwtAuthError,
          );
          expect(() => unauthed.getUnauthedHeaderClaims({ token })).toThrow(
            unauthed.SimpleJwtAuthError,
          );
          expect(() => unauthed.redactSignature({ token })).toThrow(
            unauthed.SimpleJwtAuthError,
          );
          expect(unauthed.isJSONWebToken(token)).toBe(false);
        }
      });

      then('each error names its cause, per op and per token', () => {
        const unauthed = require('simple-jwt-auth/unauthed');
        const messages = ['not-a-jwt', '', undefined].map((token) => ({
          token: token ?? '(absent)',
          getUnauthedClaims: getThrownOfCall({
            call: () => unauthed.getUnauthedClaims({ token }),
          }),
          getUnauthedHeaderClaims: getThrownOfCall({
            call: () => unauthed.getUnauthedHeaderClaims({ token }),
          }),
          redactSignature: getThrownOfCall({
            call: () => unauthed.redactSignature({ token }),
          }),
          isJSONWebToken: unauthed.isJSONWebToken(token),
        }));
        const thrownExpected = {
          name: 'SimpleJwtAuthError',
          message: 'token does not match shape of a JWT',
        };
        for (const message of messages) {
          expect(message.getUnauthedClaims).toEqual(thrownExpected);
          expect(message.getUnauthedHeaderClaims).toEqual(thrownExpected);
          expect(message.redactSignature).toEqual(thrownExpected);
          expect(message.isJSONWebToken).toBe(false);
        }
        expect(messages).toMatchSnapshot();
      });
    });

    // .note = pins the extant root behavior the readme names; a fix to SimpleJwtAuthError is .dream/v2026_11_06.repair.decode-ops-throw-raw-syntaxerror.md
    when('[t4] a jwt-shaped token whose parts do not parse is decoded', () => {
      then('each decode op throws a raw SyntaxError, as on the root', () => {
        const unauthed = require('simple-jwt-auth/unauthed');
        const root = require('simple-jwt-auth');
        const token = 'a.b.c';
        const outcome = {
          token,
          isJSONWebToken: unauthed.isJSONWebToken(token),
          getUnauthedClaims: getThrownOfCall({
            call: () => unauthed.getUnauthedClaims({ token }),
          }),
          getUnauthedHeaderClaims: getThrownOfCall({
            call: () => unauthed.getUnauthedHeaderClaims({ token }),
          }),
        };
        expect(outcome.isJSONWebToken).toBe(true);
        expect(outcome.getUnauthedClaims.name).toEqual('SyntaxError');
        expect(outcome.getUnauthedHeaderClaims.name).toEqual('SyntaxError');
        expect(
          getThrownOfCall({ call: () => root.getUnauthedClaims({ token }) }),
        ).toEqual(outcome.getUnauthedClaims);
        expect(outcome.getUnauthedClaims.message.length).toBeGreaterThan(0);

        // the message is the engine's own JSON.parse text, which varies across node versions, so mask it
        const asMasked = (thrown: { name: string }) => ({
          name: thrown.name,
          message: '<engine JSON.parse message>',
        });
        expect({
          ...outcome,
          getUnauthedClaims: asMasked(outcome.getUnauthedClaims),
          getUnauthedHeaderClaims: asMasked(outcome.getUnauthedHeaderClaims),
        }).toMatchSnapshot();
      });

      then('redact does not parse, so it redacts', () => {
        const unauthed = require('simple-jwt-auth/unauthed');
        expect(unauthed.redactSignature({ token: 'a.b.c' })).toEqual(
          'a.b.__REDACTED__',
        );
        expect(unauthed.redactSignature({ token: 'a.b.c' })).toMatchSnapshot();
      });
    });
  });
});
