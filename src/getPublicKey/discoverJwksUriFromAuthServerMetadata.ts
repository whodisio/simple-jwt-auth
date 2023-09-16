import axios from 'axios';
import jwkToPem from 'jwk-to-pem';

import { MinimalTokenClaims, SimpleJwtAuthError } from '..';

export class DiscoverJwksUriFromAuthServerMetadataError extends SimpleJwtAuthError {
  constructor({ reason }: { reason: string }) {
    const message = `
${reason}

Can not discover jwks uri from auth server metadata.
    `.trim();
    super(message);
  }
}

export const getOrThrowStandardError = async (uri: string) => {
  try {
    return await axios.get(uri);
  } catch (error) {
    throw new DiscoverJwksUriFromAuthServerMetadataError({
      reason: `Found error attempting to execute \`GET:${uri}\`: ${error.message}`,
    });
  }
};

export const jwkToPemOrThrowStandardError = (jwk: any) => {
  try {
    return jwkToPem(jwk);
  } catch (error) {
    throw new DiscoverJwksUriFromAuthServerMetadataError({
      reason: `Found error attempting to cast JWK to PEM: ${error.message}`,
    });
  }
};

export const discoverJwksUriFromAuthServerMetadata = async ({
  claims,
}: {
  claims: MinimalTokenClaims;
}) => {
  const issuer = claims.iss;

  // check that issuer defines an http(s) host
  const looksLikeUrl = new RegExp(/^https?:\/\//i).test(issuer);
  if (!looksLikeUrl)
    throw new DiscoverJwksUriFromAuthServerMetadataError({
      reason: `Issuer does not define a public server (i.e., does not start with \`http://\` or \`https://\`). Found \`${issuer}\``,
    });

  // try to find the issuer's "authorization-server-metadata" in the well known location
  const metadataAddress = `${issuer}/.well-known/oauth-authorization-server`;
  const { data: metadata } = await getOrThrowStandardError(metadataAddress);

  // check that the issuer in the auth-server-metadata matches the token's issuer
  if (metadata.issuer !== issuer)
    throw new DiscoverJwksUriFromAuthServerMetadataError({
      reason: `Token issuer does not match the issuer defined in the auth server metadata found for the issuer. This is a security concern. Found \`${metadata.issuer}\` but expected \`${issuer}\`.`,
    });

  // check that the data defines the jwkUri
  const jwksUri = metadata.jwks_uri;
  if (!jwksUri)
    throw new DiscoverJwksUriFromAuthServerMetadataError({
      reason: `Auth server metadata does not define a \`jwks_uri\``,
    });

  // return the jwks uri
  return jwksUri;
};
