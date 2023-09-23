import { given, when, then } from 'test-fns';

import { createSigningKeyPair } from './createSigningKeyPair';
import { createVerifiableSignature } from './createVerifiableSignature';
import {
  exampleEccKeyPair,
  exampleRsaKeyPair,
} from './createVerifiableSignature.test';
import { AsymmetricSigningAlgorithm } from './isAsymmetricSigningAlgorithm';
import { isSignatureVerified } from './isSignatureVerified';

describe('isSignatureVerified', () => {
  given('rsa signature', () => {
    const alg: AsymmetricSigningAlgorithm = 'RS256';
    const payload = 'hello';
    const keypair = exampleRsaKeyPair;

    when('payload and publickey are correct', () => {
      then('returns true', () => {
        const signature = createVerifiableSignature({
          alg,
          payload,
          privateKey: keypair.privateKey,
        });
        const verified = isSignatureVerified({
          alg,
          signature,
          payload,
          publicKey: keypair.publicKey,
        });
        expect(verified).toEqual(true);
      });
    });
    when('payload is incorrect', () => {
      then('returns false', () => {
        const signature = createVerifiableSignature({
          alg,
          payload,
          privateKey: keypair.privateKey,
        });
        const verified = isSignatureVerified({
          alg,
          signature,
          payload: 'tampered payload',
          publicKey: keypair.publicKey,
        });
        expect(verified).toEqual(false);
      });
    });
    when('publickey is incorrect', () => {
      then('returns false', async () => {
        const signature = createVerifiableSignature({
          alg,
          payload,
          privateKey: keypair.privateKey,
        });
        const verified = isSignatureVerified({
          alg,
          signature,
          payload,
          publicKey: (await createSigningKeyPair(alg)).publicKey,
        });
        expect(verified).toEqual(false);
      });
    });
  });

  given('ecc signature', () => {
    const alg: AsymmetricSigningAlgorithm = 'ES256';
    const payload = 'hello';
    const keypair = exampleEccKeyPair;

    when('payload and publickey are correct', () => {
      then('returns true', () => {
        const signature = createVerifiableSignature({
          alg,
          payload,
          privateKey: keypair.privateKey,
        });
        const verified = isSignatureVerified({
          alg,
          signature,
          payload,
          publicKey: keypair.publicKey,
        });
        expect(verified).toEqual(true);
      });
    });
    when('payload is incorrect', () => {
      then('returns false', () => {
        const signature = createVerifiableSignature({
          alg,
          payload,
          privateKey: keypair.privateKey,
        });
        const verified = isSignatureVerified({
          alg,
          signature,
          payload: 'tampered payload',
          publicKey: keypair.publicKey,
        });
        expect(verified).toEqual(false);
      });
    });
    when('publickey is incorrect', () => {
      then('returns false', async () => {
        const signature = createVerifiableSignature({
          alg,
          payload,
          privateKey: keypair.privateKey,
        });
        const verified = isSignatureVerified({
          alg,
          signature,
          payload,
          publicKey: (await createSigningKeyPair(alg)).publicKey,
        });
        expect(verified).toEqual(false);
      });
    });
  });
});
