import { given, then, useBeforeAll, when } from 'test-fns';

import { getThrownOfCall } from './.test/getThrownOfCall';

/**
 * .what = the claims each token in this suite carries
 * .why = valid claims, so the only fault a case can meet is the key type
 */
const CLAIMS = {
  iss: 'https://auth.example.com',
  aud: 'b2f2e7a0-0000-4000-8000-000000000000',
  sub: 'c3a3f8b1-0000-4000-8000-000000000000',
  exp: 1893456000,
};

/**
 * .what = a token with its signature segment masked
 * .why = each run signs with a fresh key pair, so the signature varies; the header and claims segments do not
 */
const asTokenWithSignatureMasked = (input: { token: string }): string =>
  [...input.token.split('.').slice(0, 2), '<signature>'].join('.');

describe('createSecureDistributedAuthToken', () => {
  given(
    '[case1] a consumer signs with simple-jwt-auth, one key pair per family',
    () => {
      const keys = useBeforeAll(async () => {
        const root = require('simple-jwt-auth');
        return {
          root,
          rsa: await root.createSigningKeyPair('RS256'),
          ec: await root.createSigningKeyPair('ES256'),
        };
      });

      when('[t0] the key fits the alg', () => {
        [
          { alg: 'RS256', kid: 'kid.rsa', family: 'rsa' as const },
          { alg: 'ES256', kid: 'kid.ec', family: 'ec' as const },
        ].map(({ alg, kid, family }) =>
          then(
            `the ${alg} token is signed with the ${family} key, and verifies with its pair`,
            () => {
              const token = keys.root.createSecureDistributedAuthToken({
                headerClaims: { alg, kid, typ: 'JWT' },
                claims: CLAIMS,
                privateKey: keys[family].privateKey,
              });
              expect(
                keys.root.getSignedClaims({
                  token,
                  publicKey: keys[family].publicKey,
                }),
              ).toEqual(CLAIMS);
              expect(asTokenWithSignatureMasked({ token })).toMatchSnapshot();
              expect({
                header: keys.root.getUnauthedHeaderClaims({ token }),
                claims: keys.root.getUnauthedClaims({ token }),
              }).toMatchSnapshot(); // the same token, decoded, so a reader checks it by eye
            },
          ),
        );
      });

      when('[t1] an ec key is given for an rsa alg', () => {
        then(
          'it fails loud, and names the key type, the alg, and the fix',
          () => {
            const thrown = getThrownOfCall({
              call: () =>
                keys.root.createSecureDistributedAuthToken({
                  headerClaims: { alg: 'RS256', kid: 'kid.rsa', typ: 'JWT' },
                  claims: CLAIMS,
                  privateKey: keys.ec.privateKey,
                }),
            });
            expect(thrown.name).toEqual('SimpleJwtAuthError');
            expect(thrown.message).toContain(
              "private key type 'ec' does not fit alg 'RS256'",
            );
            expect(thrown.message).toContain("createSigningKeyPair('RS256')");
            expect(thrown).toMatchSnapshot();
          },
        );
      });

      when('[t2] an rsa key is given for an ec alg', () => {
        then(
          'it fails loud, and names the key type, the alg, and the fix',
          () => {
            const thrown = getThrownOfCall({
              call: () =>
                keys.root.createSecureDistributedAuthToken({
                  headerClaims: { alg: 'ES256', kid: 'kid.ec', typ: 'JWT' },
                  claims: CLAIMS,
                  privateKey: keys.rsa.privateKey,
                }),
            });
            expect(thrown.name).toEqual('SimpleJwtAuthError');
            expect(thrown.message).toContain(
              "private key type 'rsa' does not fit alg 'ES256'",
            );
            expect(thrown.message).toContain("createSigningKeyPair('ES256')");
            expect(thrown).toMatchSnapshot();
          },
        );
      });
    },
  );
});
