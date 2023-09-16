import { getError } from '@ehmpathy/error-fns';
import axios from 'axios';
import { then, when } from 'test-fns';

import { getUnauthedClaims } from '../getUnauthedClaims';
import {
  discoverJwksUriFromAuthServerMetadata,
  DiscoverJwksUriFromAuthServerMetadataError,
} from './discoverJwksUriFromAuthServerMetadata';

jest.mock('axios');
const axiosGetMock = axios.get as jest.Mock;

describe('discoverJwksUriFromAuthServerMetadata', () => {
  beforeEach(() => jest.clearAllMocks());
  when(`a token's issuer is not a public host`, () => {
    const token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Il9fa2V5X2lkX18ifQ.eyJpc3MiOiJ3aG9kaXMuaW8iLCJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.mxJ5X3dmoIItWYU5ab5B0HK1DlFaJA4EX2fUQyJ_0yc`;
    const claims = getUnauthedClaims({ token });

    then(
      'we should throw an error to avoid executing an `http:get` on random strings',
      async () => {
        try {
          await discoverJwksUriFromAuthServerMetadata({ claims });
          throw new Error('should not reach here');
        } catch (error) {
          expect(error).toBeInstanceOf(
            DiscoverJwksUriFromAuthServerMetadataError,
          );
          expect(error.message).toContain(
            'Issuer does not define a public server (i.e., does not start with `http://` or `https://`). Found `whodis.io`',
          );
        }
      },
    );
  });

  when('the token.issuer !== auth server metadata.issuer', () => {
    const token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Il9fa2V5X2lkX18ifQ.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvLy4uLiIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.AvXcwdU4amvp-eQwREHAQORKAbUe-crJuJoabABS_fE`;
    const claims = getUnauthedClaims({ token });

    beforeEach(() =>
      axiosGetMock.mockReturnValue({
        data: { issuer: 'not the same issuer' },
      }),
    );
    then(
      'we should throw an error since this could be a security risk',
      async () => {
        const error = await getError(
          discoverJwksUriFromAuthServerMetadata({ claims }),
        );
        expect(error).toBeInstanceOf(
          DiscoverJwksUriFromAuthServerMetadataError,
        );
        expect(error.message).toContain(
          'Token issuer does not match the issuer defined in the auth server metadata found for the issuer. This is a security concern. Found `not the same issuer` but expected `https://auth.whodis.io/...`.',
        );
      },
    );
  });

  when('it successfully finds the jwks uri', () => {
    beforeEach(() =>
      axiosGetMock.mockReturnValue({
        data: {
          issuer: 'https://auth.whodis.io/c71b8fd1-bba7-47ee-966b-65ab85b34972',
          jwks_uri:
            'https://auth.whodis.io/c71b8fd1-bba7-47ee-966b-65ab85b34972/jwks.json',
        },
      }),
    );
    then('it should return the jwks uri it found', async () => {
      const token = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjRkLmM3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiJ9.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvL2M3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiIsInN1YiI6ImJlZWZiZWVmLWJlZWYtYmVlZi1iZWVmLWJlZWZiZWVmYmVlZiIsImF1ZCI6ImM3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiIsImlhdCI6MTYwMDYyNTMzNiwibmJmIjoxNjAwNjI1MzM2LCJleHAiOjE2MDA2Njg1MzYsInR0bCI6MTYwMTkyMTMzNn0.F58A0ARfGujb7n5KMCwcbbwPh7UcH50y6ohWDzEIJRbkMoqvfZpyn6D8xrK_hyOtM54wP7UUJrtEK-XzfzzwyvZ9EYIWEhBZhHbHWqpYTEgxvM9gDaGgvqtuc5CuManfwONZh9ETxnVjY-NaigmIjpOog8C08wQ9e_DADJsdEmtdb_y0HWBuIo1lKOwdLFfEF7RJ-9ZZ415u_MCNjxhvn4CykQBIB92LYlfnbU6MpzeMo1QG7Tt3X8J_pbsTz4TsGD58vQHq01ibp8MXSZ-KoxE7Vs5BYS7o0-vU7yhkpH1TuoapUmWBI8ZFaOr-ym8E5iBvu-xn3Ms20PFigxiyzHddm9r2Z2MWiffYPhC8xHbM1IL3kSin-2wK7_3EdQT1X7_V8mk6ZJXaqBtvtL0nAx8Zf5JBcgj-mKbPQMtUM2aneHKU7rf5BFX9F-MfJhczn5ZiowmQOJruKOsPQRHNeR87VZprD_aDP6Q_5LcklCJoz3Ol-n3I-2YccCGgwilHF7bDlv4fGQlXXdZEDDYZwdA8U_SvuxPhowPqlOheeERgBjbxdodLHOgBfMR1hsvAqOmedOVCUREM3fiN7-iA3KdStpS6C2-_NHHGUwOlc1dCgbHYMLpJ565k98drCzancl3-Od5i6B5JqaFh7_n7-34R0s0sph9fkGoznVF4ZJM`;
      const claims = getUnauthedClaims({ token });
      const jwksUri = await discoverJwksUriFromAuthServerMetadata({
        claims,
      });
      expect(jwksUri).toEqual(
        'https://auth.whodis.io/c71b8fd1-bba7-47ee-966b-65ab85b34972/jwks.json',
      );
    });
  });
});
