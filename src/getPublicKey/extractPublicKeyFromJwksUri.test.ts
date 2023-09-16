import { getError } from '@ehmpathy/error-fns';
import axios from 'axios';
import { given, then, when } from 'test-fns';

import {
  ExtractPublicKeyFromJwksUriError,
  extractPublicKeyFromJwksUri,
} from './extractPublicKeyFromJwksUri';

jest.mock('axios');
const axiosGetMock = axios.get as jest.Mock;

const realExampleJwks = [
  {
    kty: 'RSA',
    n: 'rwDJOPJ7rzu2oaixavxpfMiSr4Th_bKnMQqykmQYC6IdY-A2RMseGSaQqxpX7SBKtoFqp0WjLbD1aj2iHH2i1nFQLNXxStwTbaJiwYiB_Bpsm1KLuk0oYnIn9AwEwiGlRNTWxJFqyNI3Z-XTZakmQCx71_QQ6hL6vfx-ensNJjgCUJB9Yz-lBkF3esYLcyc2SbndshYZ_qBj-AUb-8JzILfHBQ4kXGPhiV2063RCWWBynML9y-VC1bQF0lzAuyP4CX8IdHqlzck2zD11eHIIK2Bnz8C0DhRldabsfXaGREw4SQNqadyfpXgPUL1blcQNp7IZE_l3B8Zf0yTxRgh4mCWoe1hECgzOsfuaeeBY15vBO7otLSQGYejo8q5V90fk6RpOyqeRsM0KswqqTpgNUsyvuTWzDGfTTJtKnuItcn51C4r-_oyV7ICDYbjpid8Ejmy9ABe0ndrVb5rpDI6MzbiJhfeMF5nNQMyGrEqXRzBgwIybmO3f9FMeTwwOAG0LawM3pDwJf5lldj88x9edyWF7RemWGi68JF3PGVGbDXyWtu-cL7mvecvH37x1dmHsUWRxmWm6VTEozhfdENYDmOSl0FV5xmWXEsd-SttOC1cuGZQI66EaPMck9Z_7vqJT84TCm7zsOYBQStXM6wuTA3TnCSBa4IiUvQwuNcuhiSU',
    e: 'AQAB',
    kid: '4d.c71b8fd1-bba7-47ee-966b-65ab85b34972',
  },
];
const realExampleAlternateJwks = { keys: realExampleJwks };

describe('extractPublicKeyFromJwksUri', () => {
  beforeEach(() => jest.clearAllMocks());

  given('a resolvable jwks uri', () => {
    given('the body is the array of keys directly', () => {
      beforeEach(() => axiosGetMock.mockReturnValue({ data: realExampleJwks }));

      when('the jwks has the kid of the token', () => {
        then('it should return the public key of that key', async () => {
          const publicKey = await extractPublicKeyFromJwksUri({
            jwksUri: '__jwks_uri__',
            headerClaims: {
              kid: realExampleJwks[0]?.kid,
            } as any,
          });
          expect(publicKey).toContain('-----BEGIN PUBLIC KEY-----');
        });
      });

      when('the jwks does not include the kid of the token', () => {
        then('it should throw an error reporting this', async () => {
          const error = await getError(
            extractPublicKeyFromJwksUri({
              jwksUri: '__jwks_uri__',
              headerClaims: {
                kid: '__not_to_be_found__',
              } as any,
            }),
          );
          expect(error).toBeInstanceOf(ExtractPublicKeyFromJwksUriError);
          expect(error.message).toContain(
            'Could not find a JSON Web Key (JWK) with the KeyId specified by the token ',
          );
        });
      });
    });

    given(
      'the body is an object with the jwks nested under the .keys property',
      () => {
        beforeEach(() =>
          axiosGetMock.mockReturnValue({ data: realExampleAlternateJwks }),
        );

        when('the jwks has the kid of the token', () => {
          then('it should return the public key of that key', async () => {
            const publicKey = await extractPublicKeyFromJwksUri({
              jwksUri: '__jwks_uri__',
              headerClaims: {
                kid: realExampleJwks[0]?.kid,
              } as any,
            });
            expect(publicKey).toContain('-----BEGIN PUBLIC KEY-----');
          });
        });
      },
    );
  });
});
