import { MalfunctionError } from 'helpful-errors';
import { getError, given, then, useBeforeAll, when } from 'test-fns';

import {
  ExtractPublicKeyFromJwksUriError,
  extractPublicKeyFromJwksUri,
} from './extractPublicKeyFromJwksUri';

describe('extractPublicKeyFromJwksUri', () => {
  given('a real google jwks uri', () => {
    const jwksUri = 'https://www.googleapis.com/oauth2/v3/certs';

    // google rotates its key ids, so read a current one from the live jwks
    const current = useBeforeAll(async () => {
      const jwks = (await (await fetch(jwksUri)).json()) as {
        keys: { kid: string }[];
      }; // .note = the jwks endpoint returns untyped json; `keys[].kid` is its rfc 7517 shape
      const kid = jwks.keys[0]?.kid;
      if (!kid)
        throw new MalfunctionError('google jwks lists no key', {
          jwksUri,
          hint: 'open the jwks uri above; google may have changed its endpoint',
        });
      return { kid };
    });

    when('called with a kid the jwks lists today', () => {
      then('find the correct public key', async () => {
        const publicKey = await extractPublicKeyFromJwksUri({
          jwksUri,
          headerClaims: { kid: current.kid } as any,
        });
        expect(publicKey).toContain('-----BEGIN PUBLIC KEY-----');
      });
    });

    when('called with a kid the jwks does not list', () => {
      then(
        'it fails loud, with the error class that marks an absent key id',
        async () => {
          const error = await getError(
            extractPublicKeyFromJwksUri({
              jwksUri,
              headerClaims: { kid: '__kid_absent_from_jwks__' } as any,
            }),
          );
          expect(error).toBeInstanceOf(ExtractPublicKeyFromJwksUriError);
          expect(error.message).toContain(
            'Could not find a JSON Web Key (JWK)',
          );
          expect(error.message).toMatchSnapshot();
        },
      );
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
