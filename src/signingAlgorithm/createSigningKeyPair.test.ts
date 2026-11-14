import { given, then, when } from 'test-fns';

import { createPrivateKey } from 'node:crypto';
import { createSigningKeyPair } from './createSigningKeyPair';

// rsa keygen is the subject here, and its prime search can outrun jest's 5s default under load
jest.setTimeout(30_000);

describe('createSigningKeyPair', () => {
  given('an rsa alg', () => {
    when('a key pair is created', () => {
      then('it is a 2048-bit rsa key pair', async () => {
        const keypair = await createSigningKeyPair('RS256');
        expect(keypair.publicKey.length).toEqual(451);

        // the pem length of an rsa private key varies with its integers' encodings (1700 occurs), so assert the key itself
        expect(keypair.privateKey).toContain('-----BEGIN PRIVATE KEY-----'); // pkcs8 pem, as createSigningKeyPair declares
        const privateKey = createPrivateKey(keypair.privateKey);
        expect(privateKey.asymmetricKeyType).toEqual('rsa');
        expect(privateKey.asymmetricKeyDetails?.modulusLength).toEqual(2048);
      });
    });
  });

  given('an ecc alg', () => {
    when('a key pair is created', () => {
      then('it is an ecc key pair', async () => {
        const keypair = await createSigningKeyPair('ES256');
        expect(keypair.publicKey.length).toEqual(178);
        expect(keypair.privateKey.length).toEqual(241);
      });
    });
  });
});
