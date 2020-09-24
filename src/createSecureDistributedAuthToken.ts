import { base64UrlEncode } from './base64Url/base64UrlEncode';
import { MinimalTokenClaims } from './getUnauthedClaims';
import { MinimalTokenHeaderClaims } from './getUnauthedHeaderClaims';
import { isAsymmetricSigningAlgorithm } from './signingAlgorithm/isAsymmetricSigningAlgorithm';
import { SimpleJwtAuthError } from './SimpleJwtAuthError';
import { createVerifiableSignature } from './signingAlgorithm/createVerifiableSignature';

/**
 * Creates secure, authenticatable tokens for a distributed system - enforcing security standards
 */
export const createSecureDistributedAuthToken = <C extends MinimalTokenClaims>({
  headerClaims,
  claims,
  privateKey,
}: {
  headerClaims: MinimalTokenHeaderClaims;
  claims: C;
  privateKey: string;
}): string => {
  // check that the signing algorithm is asymmetric
  if (!isAsymmetricSigningAlgorithm(headerClaims.alg))
    throw new SimpleJwtAuthError('only asymmetric signing algorithms are allowed in distributed systems');

  // check that an issuer and audience have been defined
  if (!claims.iss) throw new SimpleJwtAuthError('token.claims.iss must be defined when creating a secure token');
  if (!claims.aud) throw new SimpleJwtAuthError('token.claims.aud must be defined when creating a secure token');

  // check that expiration has been defined
  if (!claims.exp) throw new SimpleJwtAuthError('token.claims.exp must be defined when creating a secure token');

  // create a token
  const payload = [base64UrlEncode(JSON.stringify(headerClaims)), base64UrlEncode(JSON.stringify(claims))].join('.');
  const signature = createVerifiableSignature({ alg: headerClaims.alg, payload, privateKey });
  const token = [...payload.split('.'), signature].join('.');

  // return the token
  return token;
};
