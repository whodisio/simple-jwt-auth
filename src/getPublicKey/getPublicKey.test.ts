import { given, when, then } from 'test-fns';

import { getPublicKey } from '..';
import { discoverJwksUriFromAuthServerMetadata } from './discoverJwksUriFromAuthServerMetadata';
import { extractPublicKeyFromJwksUri } from './extractPublicKeyFromJwksUri';
import { cachePublicKey, getPublicKeyFromCache } from './publicKeyCache';

jest.mock('./publicKeyCache');
const cachePublicKeyMock = cachePublicKey as jest.Mock;
const getPublicKeyFromCacheMock = getPublicKeyFromCache as jest.Mock;

jest.mock('./discoverJwksUriFromAuthServerMetadata');
const discoverJwksUriFromAuthServerMetadataMock =
  discoverJwksUriFromAuthServerMetadata as jest.Mock;
discoverJwksUriFromAuthServerMetadataMock.mockReturnValue(
  '__discovered_jwks_uri__',
);

jest.mock('./extractPublicKeyFromJwksUri');
const extractPublicKeyFromJwksUriMock =
  extractPublicKeyFromJwksUri as jest.Mock;
extractPublicKeyFromJwksUriMock.mockReturnValue('__discovered_jwks_uri__');

const token = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjRkLmM3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiJ9.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvL2M3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiIsInN1YiI6ImJlZWZiZWVmLWJlZWYtYmVlZi1iZWVmLWJlZWZiZWVmYmVlZiIsImF1ZCI6ImM3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiIsImlhdCI6MTYwMDYyNTMzNiwibmJmIjoxNjAwNjI1MzM2LCJleHAiOjE2MDA2Njg1MzYsInR0bCI6MTYwMTkyMTMzNn0.F58A0ARfGujb7n5KMCwcbbwPh7UcH50y6ohWDzEIJRbkMoqvfZpyn6D8xrK_hyOtM54wP7UUJrtEK-XzfzzwyvZ9EYIWEhBZhHbHWqpYTEgxvM9gDaGgvqtuc5CuManfwONZh9ETxnVjY-NaigmIjpOog8C08wQ9e_DADJsdEmtdb_y0HWBuIo1lKOwdLFfEF7RJ-9ZZ415u_MCNjxhvn4CykQBIB92LYlfnbU6MpzeMo1QG7Tt3X8J_pbsTz4TsGD58vQHq01ibp8MXSZ-KoxE7Vs5BYS7o0-vU7yhkpH1TuoapUmWBI8ZFaOr-ym8E5iBvu-xn3Ms20PFigxiyzHddm9r2Z2MWiffYPhC8xHbM1IL3kSin-2wK7_3EdQT1X7_V8mk6ZJXaqBtvtL0nAx8Zf5JBcgj-mKbPQMtUM2aneHKU7rf5BFX9F-MfJhczn5ZiowmQOJruKOsPQRHNeR87VZprD_aDP6Q_5LcklCJoz3Ol-n3I-2YccCGgwilHF7bDlv4fGQlXXdZEDDYZwdA8U_SvuxPhowPqlOheeERgBjbxdodLHOgBfMR1hsvAqOmedOVCUREM3fiN7-iA3KdStpS6C2-_NHHGUwOlc1dCgbHYMLpJ565k98drCzancl3-Od5i6B5JqaFh7_n7-34R0s0sph9fkGoznVF4ZJM`;

describe('getPublicKey', () => {
  beforeEach(() => jest.clearAllMocks());

  given('the token is not already cached', () => {
    // nothing in the cache
    beforeEach(() => {
      getPublicKeyFromCacheMock.mockReturnValue(undefined);
    });

    when('the jwks uri needs to be discovered', () => {
      it('the jwks uri discovery flow should be invoked', async () => {
        await getPublicKey({ token });
        expect(discoverJwksUriFromAuthServerMetadataMock).toHaveBeenCalledTimes(
          1,
        );
      });
      then(
        'the public key should be extracted from the discovered jwks uri',
        async () => {
          await getPublicKey({ token });
          expect(extractPublicKeyFromJwksUri).toHaveBeenCalledTimes(1);
          expect(extractPublicKeyFromJwksUri).toHaveBeenCalledWith(
            expect.objectContaining({ jwksUri: '__discovered_jwks_uri__' }),
          );
        },
      );
    });
    when('the jwks uri is explicitly defined', () => {
      then('the jwks uri discovery flow should be skipped', async () => {
        await getPublicKey({ token, jwksUri: '__explicit_jwks_uri__' });
        expect(discoverJwksUriFromAuthServerMetadataMock).toHaveBeenCalledTimes(
          0,
        );
      });
      then(
        'the public key should be extracted from then defined jwks uri',
        async () => {
          await getPublicKey({ token, jwksUri: '__explicit_jwks_uri__' });
          expect(extractPublicKeyFromJwksUri).toHaveBeenCalledTimes(1);
          expect(extractPublicKeyFromJwksUri).toHaveBeenCalledWith(
            expect.objectContaining({ jwksUri: '__explicit_jwks_uri__' }),
          );
        },
      );
    });

    then('the token should be cached for subsequent lookups', async () => {
      const publicKey = await getPublicKey({
        token,
        jwksUri: '__explicit_jwks_uri__',
      });
      expect(cachePublicKeyMock).toHaveBeenCalledWith({
        issuer: 'https://auth.whodis.io/c71b8fd1-bba7-47ee-966b-65ab85b34972',
        keyId: '4d.c71b8fd1-bba7-47ee-966b-65ab85b34972',
        publicKey,
        ttlInSeconds: 300, // the default to cache w/
      });
    });
  });

  given('the token is already cached', () => {
    // mock that its already cached
    beforeEach(() =>
      getPublicKeyFromCacheMock.mockReturnValue('__PUBLIC_KEY_FROM_CACHE__'),
    );

    then('the jwks uri discovery flow should not be invoked', async () => {
      await getPublicKey({ token });
      expect(discoverJwksUriFromAuthServerMetadataMock).toHaveBeenCalledTimes(
        0,
      );
    });
    then('the public key extraction flow should not be invoked', async () => {
      await getPublicKey({ token });
      expect(extractPublicKeyFromJwksUri).toHaveBeenCalledTimes(0);
    });

    then('it should return the cached public key', async () => {
      const publicKey = await getPublicKey({
        token,
      });
      expect(publicKey).toEqual('__PUBLIC_KEY_FROM_CACHE__');
    });
  });
});
