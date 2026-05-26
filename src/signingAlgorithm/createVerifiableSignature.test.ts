import { getError, given, then, when } from 'test-fns';

import {
  exampleEccKeyPair,
  exampleRsaKeyPair,
} from '@src/.test/assets/exampleKeyPairs';

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
      // TODO: add additional safety by throwing an error if wrong key type is given
      then.skip('throw an error', async () => {
        const error = getError(() =>
          createVerifiableSignature({
            alg,
            payload,
            privateKey: exampleEccKeyPair.privateKey,
          }),
        );
        expect(error.message).toContain('todo');
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
      // TODO: add additional safety by throwing an error if wrong key type is given
      then.skip('throw an error', async () => {
        const error = getError(() =>
          createVerifiableSignature({
            alg,
            payload,
            privateKey: exampleRsaKeyPair.privateKey,
          }),
        );
        expect(error.message).toContain('todo');
      });
    });
  });
});
