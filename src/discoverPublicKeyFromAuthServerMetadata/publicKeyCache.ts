import { createCache } from 'simple-in-memory-cache';

const publicKeyCache = createCache({ defaultSecondsUntilExpiration: 5 * 60 }); // cache public keys for up to 5 min

export const cachePublicKey = ({
  issuer,
  keyId,
  publicKey,
  ttlInSeconds,
}: {
  issuer: string;
  keyId: string;
  publicKey: string;
  ttlInSeconds?: number;
}) =>
  publicKeyCache.set(`${issuer}:${keyId}`, publicKey, {
    secondsUntilExpiration: ttlInSeconds,
  });

export const getPublicKeyFromCache = ({
  issuer,
  keyId,
}: {
  issuer: string;
  keyId: string;
}) => publicKeyCache.get(`${issuer}:${keyId}`);
