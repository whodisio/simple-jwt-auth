import { getError, given, then, when } from 'test-fns';

import {
  exampleEccKeyPair,
  exampleRsaKeyPair,
} from '@src/.test/assets/exampleKeyPairs';
import { SimpleJwtAuthError } from '@src/SimpleJwtAuthError';

import { createVerifiableSignature } from './createVerifiableSignature';
import type { AsymmetricSigningAlgorithm } from './isAsymmetricSigningAlgorithm';
import { isSignatureVerified } from './isSignatureVerified';

describe('createVerifiableSignature', () => {
  const payload = 'hello';

  given('rsa algorithm', () => {
    const alg: AsymmetricSigningAlgorithm = 'RS256';

    when('provided an rsa key', () => {
      then('create verifiable signature', () => {
        const signature = createVerifiableSignature({
          alg,
          payload,
          privateKey: exampleRsaKeyPair.privateKey,
        });

        // check that its deterministic
        expect(signature).toMatchSnapshot(); // should be deterministic

        // check that it is verifiable
        const verified = isSignatureVerified({
          alg,
          payload,
          signature,
          publicKey: exampleRsaKeyPair.publicKey,
        });
        expect(verified).toEqual(true);
      });
    });

    when('provided an ecc key', () => {
      then('throw an error', () => {
        const error = getError(() =>
          createVerifiableSignature({
            alg,
            payload,
            privateKey: exampleEccKeyPair.privateKey,
          }),
        );
        expect(error).toBeInstanceOf(SimpleJwtAuthError);
        expect(error.message).toContain(
          "private key type 'ec' does not fit alg 'RS256'",
        );
        expect(error.message).toMatchSnapshot();
      });
    });
  });

  given('ecc algorithm', () => {
    const alg: AsymmetricSigningAlgorithm = 'ES256';

    when('provided an ecc key', () => {
      then('create verifiable signature', async () => {
        const signature = createVerifiableSignature({
          alg,
          payload,
          privateKey: exampleEccKeyPair.privateKey,
        });

        // note that ecc signatures are _not_ deterministic, so just sanity check the length looks right
        expect(signature.length).toEqual(86);

        // check that it is verifiable
        const verified = isSignatureVerified({
          alg,
          payload,
          signature,
          publicKey: exampleEccKeyPair.publicKey,
        });
        expect(verified).toEqual(true);
      });
    });

    when('provided an rsa key', () => {
      then('throw an error', () => {
        const error = getError(() =>
          createVerifiableSignature({
            alg,
            payload,
            privateKey: exampleRsaKeyPair.privateKey,
          }),
        );
        expect(error).toBeInstanceOf(SimpleJwtAuthError);
        expect(error.message).toContain(
          "private key type 'rsa' does not fit alg 'ES256'",
        );
        expect(error.message).toMatchSnapshot();
      });
    });
  });
});
