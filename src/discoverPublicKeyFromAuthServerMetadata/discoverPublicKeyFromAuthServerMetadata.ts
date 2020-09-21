import axios from 'axios';
import jwkToPem from 'jwk-to-pem';

import { SimpleJwtAuthError } from '../errors';
import { getUnauthedClaims } from '../getUnauthedClaims';
import { getUnauthedHeaderClaims } from '../getUnauthedHeaderClaims';
import { getPublicKeyFromCache, cachePublicKey } from './publicKeyCache';

export class DiscoverPublicKeyFromAuthServerMetadataError extends SimpleJwtAuthError {
  constructor({ reason }: { reason: string }) {
    const message = `
${reason}

Can not discover public key from auth server metadata.
    `.trim();
    super(message);
  }
}

export const getOrThrowStandardError = async (uri: string) => {
  try {
    return await axios.get(uri);
  } catch (error) {
    throw new DiscoverPublicKeyFromAuthServerMetadataError({
      reason: `Found error attempting to execute \`GET:${uri}\`: ${error.message}`,
    });
  }
};

export const jwkToPemOrThrowStandardError = (jwk: any) => {
  try {
    return jwkToPem(jwk);
  } catch (error) {
    throw new DiscoverPublicKeyFromAuthServerMetadataError({
      reason: `Found error attempting to cast JWK to PEM: ${error.message}`,
    });
  }
};

export const discoverPublicKeyFromAuthServerMetadata = async ({
  token,
  cache = { ttlInSeconds: 300 },
}: {
  token: string;
  cache?: { ttlInSeconds: number };
}) => {
  // grab the issuer from the token
  const claims = getUnauthedClaims({ token });
  const issuer = claims.iss;
  if (!issuer)
    throw new DiscoverPublicKeyFromAuthServerMetadataError({
      reason: 'Issuer not defined on the token (i.e., no `claims.iss`).',
    });

  // grab the keyId from the token
  const headerClaims = getUnauthedHeaderClaims({ token });
  const keyId = headerClaims.kid;
  if (!keyId) throw new DiscoverPublicKeyFromAuthServerMetadataError({ reason: 'KeyId is not defined on the token (i.e., no `header.kid`)' });

  // try to return the public key if we already have it in the cache
  const cachedKey = getPublicKeyFromCache({ issuer, keyId });
  if (cachedKey) return cachedKey; // if we got it, we got it

  // check that issuer defines an http(s) host
  const looksLikeUrl = new RegExp(/^https?:\/\//i).test(issuer);
  if (!looksLikeUrl)
    throw new DiscoverPublicKeyFromAuthServerMetadataError({
      reason: `Issuer does not define a public server (i.e., does not start with \`http://\` or \`https://\`). Found \`${issuer}\``,
    });

  // try to find the issuer's "authorization-server-metadata" in the well known location
  const metadataAddress = `${issuer}/.well-known/oauth-authorization-server`;
  const { data: metadata } = await getOrThrowStandardError(metadataAddress);

  // check that the issuer in the auth-server-metadata matches the token's issuer
  if (metadata.issuer !== issuer)
    throw new DiscoverPublicKeyFromAuthServerMetadataError({
      reason: `Token issuer does not match the issuer defined in the auth server metadata found for the issuer. This is a security concern. Found \`${metadata.issuer}\` but expected \`${issuer}\`.`,
    });

  // check that the data defines the jwkUri
  const jwksUri = metadata.jwks_uri;
  if (!jwksUri)
    throw new DiscoverPublicKeyFromAuthServerMetadataError({
      reason: `Auth server metadata does not define a \`jwks_uri\``,
    });

  // lookup the jwks with this uri
  const { data: jwks } = await getOrThrowStandardError(jwksUri);

  // try to find the jwk of this token
  if (!Array.isArray(jwks))
    throw new DiscoverPublicKeyFromAuthServerMetadataError({
      reason: 'The JSON Web Key Set (JWKS) specified by the Auth Server Metadata is malformed. It is not an array.',
    });
  const jwk = jwks.find((thisJwk) => thisJwk.kid === keyId);
  if (!jwk)
    throw new DiscoverPublicKeyFromAuthServerMetadataError({
      reason:
        'Could not find a JSON Web Key (JWK) with the KeyId specified by the token (`token.header.kid`) in the JSON Web Key Set (JWKS) specified by the Auth Server Metadata',
    });

  // convert the jwk into a pem cert, since most libs expect pem
  const publicKey = jwkToPemOrThrowStandardError(jwk);

  // cache the public key for future lookups (to save on the two HTTP calls)
  cachePublicKey({ issuer, keyId, publicKey, ttlInSeconds: cache.ttlInSeconds });

  // return the pem cert
  return publicKey; // this is the public key
};
