import { SimpleJwtAuthError } from '../SimpleJwtAuthError';
import { MinimalTokenHeaderClaims } from '../getUnauthedHeaderClaims';
import {
  getOrThrowStandardError,
  jwkToPemOrThrowStandardError,
} from './discoverJwksUriFromAuthServerMetadata';

export class ExtractPublicKeyFromJwksUriError extends SimpleJwtAuthError {
  constructor({ reason }: { reason: string }) {
    const message = `
${reason}

Can not extract public key from jwks uri.
    `.trim();
    super(message);
  }
}

/**
 * extracts the public key of a token from a jwks uri
 */
export const extractPublicKeyFromJwksUri = async ({
  headerClaims,
  jwksUri,
}: {
  headerClaims: MinimalTokenHeaderClaims;
  jwksUri: string;
}) => {
  // lookup the jwks with this uri
  const { data } = await getOrThrowStandardError(jwksUri);
  const jwks = Array.isArray(data) ? data : data.keys; // try checking both the "keys" property as well as checking if the whole thing is an array

  // try to find the jwk of this token
  if (!Array.isArray(jwks))
    throw new ExtractPublicKeyFromJwksUriError({
      reason:
        'The JSON Web Key Set (JWKS) specified by the Auth Server Metadata is malformed. It is not an array.',
    });
  const jwk = jwks.find((thisJwk) => thisJwk.kid === headerClaims.kid);
  if (!jwk)
    throw new ExtractPublicKeyFromJwksUriError({
      reason:
        'Could not find a JSON Web Key (JWK) with the KeyId specified by the token (`token.header.kid`) in the JSON Web Key Set (JWKS) specified by the Auth Server Metadata',
    });

  // convert the jwk into a pem cert, since most libs expect pem
  const publicKey = jwkToPemOrThrowStandardError(jwk);

  // return the public key
  return publicKey;
};
