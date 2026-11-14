import { given, then, when } from 'test-fns';

import {
  exampleEccKeyPair,
  exampleRsaKeyPair,
} from '@src/.test/assets/exampleKeyPairs';

import { createPublicKey } from 'node:crypto';
import { createSigningKeyPair } from './createSigningKeyPair';
import { createVerifiableSignature } from './createVerifiableSignature';
import type { AsymmetricSigningAlgorithm } from './isAsymmetricSigningAlgorithm';
import { isSignatureVerified } from './isSignatureVerified';

// a 4096-bit rsa public key of another pair, the same size as the signer's fixture pair, from a public jwk; a fresh rsa keygen in the test can outrun the 5s timeout under load
const exampleRsaPublicKeyObjectOfOtherPair = createPublicKey({
  key: {
    kty: 'RSA',
    n: 'rwDJOPJ7rzu2oaixavxpfMiSr4Th_bKnMQqykmQYC6IdY-A2RMseGSaQqxpX7SBKtoFqp0WjLbD1aj2iHH2i1nFQLNXxStwTbaJiwYiB_Bpsm1KLuk0oYnIn9AwEwiGlRNTWxJFqyNI3Z-XTZakmQCx71_QQ6hL6vfx-ensNJjgCUJB9Yz-lBkF3esYLcyc2SbndshYZ_qBj-AUb-8JzILfHBQ4kXGPhiV2063RCWWBynML9y-VC1bQF0lzAuyP4CX8IdHqlzck2zD11eHIIK2Bnz8C0DhRldabsfXaGREw4SQNqadyfpXgPUL1blcQNp7IZE_l3B8Zf0yTxRgh4mCWoe1hECgzOsfuaeeBY15vBO7otLSQGYejo8q5V90fk6RpOyqeRsM0KswqqTpgNUsyvuTWzDGfTTJtKnuItcn51C4r-_oyV7ICDYbjpid8Ejmy9ABe0ndrVb5rpDI6MzbiJhfeMF5nNQMyGrEqXRzBgwIybmO3f9FMeTwwOAG0LawM3pDwJf5lldj88x9edyWF7RemWGi68JF3PGVGbDXyWtu-cL7mvecvH37x1dmHsUWRxmWm6VTEozhfdENYDmOSl0FV5xmWXEsd-SttOC1cuGZQI66EaPMck9Z_7vqJT84TCm7zsOYBQStXM6wuTA3TnCSBa4IiUvQwuNcuhiSU',
    e: 'AQAB',
  },
  format: 'jwk',
});
const exampleRsaPublicKeyOfOtherPair = exampleRsaPublicKeyObjectOfOtherPair
  .export({ type: 'spki', format: 'pem' })
  .toString();

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
      then('returns false', () => {
        const signature = createVerifiableSignature({
          alg,
          payload,
          privateKey: keypair.privateKey,
        });
        expect(exampleRsaPublicKeyOfOtherPair).not.toEqual(keypair.publicKey);
        expect(
          exampleRsaPublicKeyObjectOfOtherPair.asymmetricKeyDetails
            ?.modulusLength,
        ).toEqual(
          createPublicKey(keypair.publicKey).asymmetricKeyDetails
            ?.modulusLength,
        ); // same size as the signer's key, so a false comes from the wrong key, not a length mismatch
        const verified = isSignatureVerified({
          alg,
          signature,
          payload,
          publicKey: exampleRsaPublicKeyOfOtherPair,
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
