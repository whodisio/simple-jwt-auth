import { given, then, when } from 'test-fns';

import { extractPublicKeyFromJwksUri } from './extractPublicKeyFromJwksUri';

describe('extractPublicKeyFromJwksUri', () => {
  // todo: update test to handle fact that google rotates kids (key-ids)
  given.skip('a real google jwks uri', () => {
    when('called with a real kid in the jwks defined in the file', () => {
      then('find the correct public key', async () => {
        const publicKey = await extractPublicKeyFromJwksUri({
          jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
          headerClaims: {
            kid: '838c06c62046c2d948affe137dd5310129f4d5d1',
          } as any,
        });
        expect(publicKey).toContain('-----BEGIN PUBLIC KEY-----');
      });
    });
  });
  given('a real whodis jwks uri', () => {
    when('called with a real kid in the jwks defined in the file', () => {
      then('find the correct public key', async () => {
        const publicKey = await extractPublicKeyFromJwksUri({
          jwksUri:
            'https://oauth.whodis.io/32b8b554-12f5-4f9b-9f16-b13e0b532019/.well-known/jwks.json',
          headerClaims: {
            kid: '4d.32b8b554-12f5-4f9b-9f16-b13e0b532019',
          } as any,
        });
        expect(publicKey).toContain('-----BEGIN PUBLIC KEY-----');
      });
    });
  });
});
