import crypto from 'crypto';

import { base64UrlEncode } from './base64Url/base64UrlEncode';
import { castBase64ToBase64Url } from './base64Url/castBase64ToBase64Url';
import { MinimalTokenClaims } from './getUnauthedClaims';
import { MinimalTokenHeaderClaims } from './getUnauthedHeaderClaims';
import { castJwtAlgToCryptoAlg } from './signingAlgorithm/castJwtAlgToCryptoAlg';
import { isAsymmetricSigningAlgorithm } from './signingAlgorithm/isAsymmetricSigningAlgorithm';
import { SimpleJwtAuthError } from './SimpleJwtAuthError';

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
  const cryptoAlg = castJwtAlgToCryptoAlg(headerClaims.alg);
  const payload = [base64UrlEncode(JSON.stringify(headerClaims)), base64UrlEncode(JSON.stringify(claims))].join('.');
  const signatureBuffer = crypto.createSign(cryptoAlg).update(payload).sign(privateKey);
  const signature = castBase64ToBase64Url(signatureBuffer.toString('base64'));
  const token = [...payload.split('.'), signature].join('.');

  // return the token
  return token;
};
