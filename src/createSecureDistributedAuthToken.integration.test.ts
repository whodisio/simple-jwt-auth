import { given } from 'test-fns';

import { createSecureDistributedAuthToken } from './createSecureDistributedAuthToken';
import { getAuthedClaims } from './getAuthedClaims';
import { getPublicKey } from './getPublicKey/getPublicKey';
import {
  exampleEccKeyPair,
  exampleRsaKeyPair,
} from './signingAlgorithm/createVerifiableSignature.test';
import { AsymmetricSigningAlgorithm } from './signingAlgorithm/isAsymmetricSigningAlgorithm';

// mock that we discover the real public key each time
jest.mock('./getPublicKey/getPublicKey');
const getPublicKeyMock = getPublicKey as jest.Mock;

describe('createSecureToken', () => {
  given('rsa signing algorithm', () => {
    const alg: AsymmetricSigningAlgorithm = 'RS256';
    const keypair = exampleRsaKeyPair;

    beforeEach(() => {
      getPublicKeyMock.mockReturnValue(keypair.publicKey);
    });

    it('should be able to create a token that we can later getAuthedClaims on', async () => {
      // create a token
      const token = createSecureDistributedAuthToken({
        headerClaims: { alg, kid: '4.some_directory', typ: 'JWT' },
        claims: {
          iss: 'https://auth.whodis.io/...',
          aud: '__some_directory__',
          sub: '__some_user__',
          exp: 2516239022,
        },
        privateKey: keypair.privateKey,
      });
      expect(typeof token).toEqual('string'); // sanity check

      // check that we can auth on it, if the publicKey is discoverable
      const claims = await getAuthedClaims({
        token,
        issuer: 'https://auth.whodis.io/...',
        audience: '__some_directory__',
      });
      expect(claims).toEqual({
        iss: 'https://auth.whodis.io/...',
        aud: '__some_directory__',
        sub: '__some_user__',
        exp: 2516239022,
      });
    });
  });

  given('ecc signing algorithm', () => {
    const alg: AsymmetricSigningAlgorithm = 'ES256';
    const keypair = exampleEccKeyPair;

    beforeEach(() => {
      getPublicKeyMock.mockReturnValue(keypair.publicKey);
    });

    it('should be able to create a token that we can later getAuthedClaims on', async () => {
      // create a token
      const token = createSecureDistributedAuthToken({
        headerClaims: { alg, kid: '4.some_directory', typ: 'JWT' },
        claims: {
          iss: 'https://auth.whodis.io/...',
          aud: '__some_directory__',
          sub: '__some_user__',
          exp: 2516239022,
        },
        privateKey: keypair.privateKey,
      });
      expect(typeof token).toEqual('string'); // sanity check

      // check that we can auth on it, if the publicKey is discoverable
      const claims = await getAuthedClaims({
        token,
        issuer: 'https://auth.whodis.io/...',
        audience: '__some_directory__',
      });
      expect(claims).toEqual({
        iss: 'https://auth.whodis.io/...',
        aud: '__some_directory__',
        sub: '__some_user__',
        exp: 2516239022,
      });
    });
  });
});
