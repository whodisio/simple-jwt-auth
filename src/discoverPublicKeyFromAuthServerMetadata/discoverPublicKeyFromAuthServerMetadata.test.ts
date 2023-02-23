import axios from 'axios';

import {
  discoverPublicKeyFromAuthServerMetadata,
  DiscoverPublicKeyFromAuthServerMetadataError,
} from './discoverPublicKeyFromAuthServerMetadata';
import { cachePublicKey, getPublicKeyFromCache } from './publicKeyCache';

jest.mock('axios');
const axiosGetMock = axios.get as jest.Mock;

jest.mock('./publicKeyCache');
const cachePublicKeyMock = cachePublicKey as jest.Mock;
const getPublicKeyFromCacheMock = getPublicKeyFromCache as jest.Mock;

const realExampleJwks = [
  {
    kty: 'RSA',
    n: 'rwDJOPJ7rzu2oaixavxpfMiSr4Th_bKnMQqykmQYC6IdY-A2RMseGSaQqxpX7SBKtoFqp0WjLbD1aj2iHH2i1nFQLNXxStwTbaJiwYiB_Bpsm1KLuk0oYnIn9AwEwiGlRNTWxJFqyNI3Z-XTZakmQCx71_QQ6hL6vfx-ensNJjgCUJB9Yz-lBkF3esYLcyc2SbndshYZ_qBj-AUb-8JzILfHBQ4kXGPhiV2063RCWWBynML9y-VC1bQF0lzAuyP4CX8IdHqlzck2zD11eHIIK2Bnz8C0DhRldabsfXaGREw4SQNqadyfpXgPUL1blcQNp7IZE_l3B8Zf0yTxRgh4mCWoe1hECgzOsfuaeeBY15vBO7otLSQGYejo8q5V90fk6RpOyqeRsM0KswqqTpgNUsyvuTWzDGfTTJtKnuItcn51C4r-_oyV7ICDYbjpid8Ejmy9ABe0ndrVb5rpDI6MzbiJhfeMF5nNQMyGrEqXRzBgwIybmO3f9FMeTwwOAG0LawM3pDwJf5lldj88x9edyWF7RemWGi68JF3PGVGbDXyWtu-cL7mvecvH37x1dmHsUWRxmWm6VTEozhfdENYDmOSl0FV5xmWXEsd-SttOC1cuGZQI66EaPMck9Z_7vqJT84TCm7zsOYBQStXM6wuTA3TnCSBa4IiUvQwuNcuhiSU',
    e: 'AQAB',
    kid: '4d.c71b8fd1-bba7-47ee-966b-65ab85b34972',
  },
];

describe('discoverPublicKeyFromAuthServerMetadata', () => {
  beforeEach(() => jest.clearAllMocks());
  describe('validation required for security', () => {
    it('should throw an error if tokens issuer is not a public host, since we dont want to `http:get` on random strings', async () => {
      const token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Il9fa2V5X2lkX18ifQ.eyJpc3MiOiJ3aG9kaXMuaW8iLCJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.mxJ5X3dmoIItWYU5ab5B0HK1DlFaJA4EX2fUQyJ_0yc`;
      try {
        await discoverPublicKeyFromAuthServerMetadata({ token });
        throw new Error('should not reach here');
      } catch (error) {
        expect(error).toBeInstanceOf(
          DiscoverPublicKeyFromAuthServerMetadataError,
        );
        expect(error.message).toContain(
          'Issuer does not define a public server (i.e., does not start with `http://` or `https://`). Found `whodis.io`',
        );
      }
    });
    it('should throw an error if token.issuer !== auth server metadata.issuer, since this could be a security risk', async () => {
      axiosGetMock.mockReturnValueOnce({
        data: { issuer: 'not the same issuer' },
      });
      const token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Il9fa2V5X2lkX18ifQ.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvLy4uLiIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.AvXcwdU4amvp-eQwREHAQORKAbUe-crJuJoabABS_fE`;
      try {
        await discoverPublicKeyFromAuthServerMetadata({ token });
        throw new Error('should not reach here');
      } catch (error) {
        expect(error).toBeInstanceOf(
          DiscoverPublicKeyFromAuthServerMetadataError,
        );
        expect(error.message).toContain(
          'Token issuer does not match the issuer defined in the auth server metadata found for the issuer. This is a security concern. Found `not the same issuer` but expected `https://auth.whodis.io/...`.',
        );
      }
    });
  });
  describe('caching', () => {
    it('should fetch the public key for the (issuer, keyId) from memory if its not already cached', async () => {
      axiosGetMock.mockReturnValueOnce({
        data: {
          issuer: 'https://auth.whodis.io/c71b8fd1-bba7-47ee-966b-65ab85b34972',
          jwks_uri:
            'https://auth.whodis.io/c71b8fd1-bba7-47ee-966b-65ab85b34972/jwks.json',
        },
      });
      axiosGetMock.mockReturnValueOnce({ data: realExampleJwks });
      const token = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjRkLmM3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiJ9.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvL2M3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiIsInN1YiI6ImJlZWZiZWVmLWJlZWYtYmVlZi1iZWVmLWJlZWZiZWVmYmVlZiIsImF1ZCI6ImM3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiIsImlhdCI6MTYwMDYyNTMzNiwibmJmIjoxNjAwNjI1MzM2LCJleHAiOjE2MDA2Njg1MzYsInR0bCI6MTYwMTkyMTMzNn0.F58A0ARfGujb7n5KMCwcbbwPh7UcH50y6ohWDzEIJRbkMoqvfZpyn6D8xrK_hyOtM54wP7UUJrtEK-XzfzzwyvZ9EYIWEhBZhHbHWqpYTEgxvM9gDaGgvqtuc5CuManfwONZh9ETxnVjY-NaigmIjpOog8C08wQ9e_DADJsdEmtdb_y0HWBuIo1lKOwdLFfEF7RJ-9ZZ415u_MCNjxhvn4CykQBIB92LYlfnbU6MpzeMo1QG7Tt3X8J_pbsTz4TsGD58vQHq01ibp8MXSZ-KoxE7Vs5BYS7o0-vU7yhkpH1TuoapUmWBI8ZFaOr-ym8E5iBvu-xn3Ms20PFigxiyzHddm9r2Z2MWiffYPhC8xHbM1IL3kSin-2wK7_3EdQT1X7_V8mk6ZJXaqBtvtL0nAx8Zf5JBcgj-mKbPQMtUM2aneHKU7rf5BFX9F-MfJhczn5ZiowmQOJruKOsPQRHNeR87VZprD_aDP6Q_5LcklCJoz3Ol-n3I-2YccCGgwilHF7bDlv4fGQlXXdZEDDYZwdA8U_SvuxPhowPqlOheeERgBjbxdodLHOgBfMR1hsvAqOmedOVCUREM3fiN7-iA3KdStpS6C2-_NHHGUwOlc1dCgbHYMLpJ565k98drCzancl3-Od5i6B5JqaFh7_n7-34R0s0sph9fkGoznVF4ZJM`;
      const publicKey = await discoverPublicKeyFromAuthServerMetadata({
        token,
      });
      expect(cachePublicKeyMock).toHaveBeenCalledWith({
        issuer: 'https://auth.whodis.io/c71b8fd1-bba7-47ee-966b-65ab85b34972',
        keyId: '4d.c71b8fd1-bba7-47ee-966b-65ab85b34972',
        publicKey,
        ttlInSeconds: 300, // the default to cache w/
      });
    });
    it('should return the public key for the (issuer, keyId) from memory if its already cached', async () => {
      getPublicKeyFromCacheMock.mockReturnValueOnce(
        '__PUBLIC_KEY_FROM_CACHE__',
      );
      const token = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjRkLmM3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiJ9.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvL2M3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiIsInN1YiI6ImJlZWZiZWVmLWJlZWYtYmVlZi1iZWVmLWJlZWZiZWVmYmVlZiIsImF1ZCI6ImM3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiIsImlhdCI6MTYwMDYyNTMzNiwibmJmIjoxNjAwNjI1MzM2LCJleHAiOjE2MDA2Njg1MzYsInR0bCI6MTYwMTkyMTMzNn0.F58A0ARfGujb7n5KMCwcbbwPh7UcH50y6ohWDzEIJRbkMoqvfZpyn6D8xrK_hyOtM54wP7UUJrtEK-XzfzzwyvZ9EYIWEhBZhHbHWqpYTEgxvM9gDaGgvqtuc5CuManfwONZh9ETxnVjY-NaigmIjpOog8C08wQ9e_DADJsdEmtdb_y0HWBuIo1lKOwdLFfEF7RJ-9ZZ415u_MCNjxhvn4CykQBIB92LYlfnbU6MpzeMo1QG7Tt3X8J_pbsTz4TsGD58vQHq01ibp8MXSZ-KoxE7Vs5BYS7o0-vU7yhkpH1TuoapUmWBI8ZFaOr-ym8E5iBvu-xn3Ms20PFigxiyzHddm9r2Z2MWiffYPhC8xHbM1IL3kSin-2wK7_3EdQT1X7_V8mk6ZJXaqBtvtL0nAx8Zf5JBcgj-mKbPQMtUM2aneHKU7rf5BFX9F-MfJhczn5ZiowmQOJruKOsPQRHNeR87VZprD_aDP6Q_5LcklCJoz3Ol-n3I-2YccCGgwilHF7bDlv4fGQlXXdZEDDYZwdA8U_SvuxPhowPqlOheeERgBjbxdodLHOgBfMR1hsvAqOmedOVCUREM3fiN7-iA3KdStpS6C2-_NHHGUwOlc1dCgbHYMLpJ565k98drCzancl3-Od5i6B5JqaFh7_n7-34R0s0sph9fkGoznVF4ZJM`;
      const publicKey = await discoverPublicKeyFromAuthServerMetadata({
        token,
      });
      expect(publicKey).toEqual('__PUBLIC_KEY_FROM_CACHE__');
      expect(axiosGetMock).not.toHaveBeenCalled(); // since we got it from cache, yay - we saved on bandwidth and latency!
    });
  });
});
