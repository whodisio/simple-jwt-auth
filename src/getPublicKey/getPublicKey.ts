import { SimpleJwtAuthError } from '../SimpleJwtAuthError';
import { getUnauthedClaims } from '../getUnauthedClaims';
import { getUnauthedHeaderClaims } from '../getUnauthedHeaderClaims';
import { discoverJwksUriFromAuthServerMetadata } from './discoverJwksUriFromAuthServerMetadata';
import { extractPublicKeyFromJwksUri } from './extractPublicKeyFromJwksUri';
import { cachePublicKey, getPublicKeyFromCache } from './publicKeyCache';

export class GetPublicKeyOfTokenError extends SimpleJwtAuthError {
  constructor({ reason }: { reason: string }) {
    const message = `
${reason}

Can not get public key of token
    `.trim();
    super(message);
  }
}

/**
 * gets the public key used to sign the token
 *
 * note
 * - caches the results to prevent redundant network requests
 * - supports oauth discovery flow, to discover the jwks endpoint from the issuer
 * - supports manual flow, to explicitly define the jwks endpoint for issuers who dont support discovery
 */
export const getPublicKey = async ({
  token,
  jwksUri: jwksUriInput,
  cache = { ttlInSeconds: 300 },
}: {
  token: string;
  jwksUri?: string;
  cache?: { ttlInSeconds: number };
}) => {
  // grab the issuer from the token
  const claims = getUnauthedClaims({ token });
  const issuer = claims.iss;
  if (!issuer)
    throw new GetPublicKeyOfTokenError({
      reason: 'Issuer not defined on the token (i.e., no `claims.iss`).',
    });

  // grab the keyId from the token
  const headerClaims = getUnauthedHeaderClaims({ token });
  const keyId = headerClaims.kid;
  if (!keyId)
    throw new GetPublicKeyOfTokenError({
      reason: 'KeyId is not defined on the token (i.e., no `header.kid`)',
    });

  // try to return the public key if we already have it in the cache
  const cachedKey = getPublicKeyFromCache({ issuer, keyId });
  if (cachedKey) return cachedKey; // if we got it, we got it

  // otherwise, lookup the public key
  const jwksUri =
    jwksUriInput ?? (await discoverJwksUriFromAuthServerMetadata({ claims }));
  const publicKey = await extractPublicKeyFromJwksUri({
    headerClaims,
    jwksUri,
  });

  // cache the public key for future lookups (to save on the two HTTP calls)
  cachePublicKey({
    issuer,
    keyId,
    publicKey,
    ttlInSeconds: cache.ttlInSeconds,
  });

  // return the pem cert
  return publicKey; // this is the public key
};
