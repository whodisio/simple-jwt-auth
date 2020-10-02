import { base64UrlDecode } from './base64Url/base64UrlDecode';
import { AsymmetricSigningAlgorithm } from './signingAlgorithm/isAsymmetricSigningAlgorithm';
import { verifyTokenShape } from './verification/verifyTokenShape';

/**
 * Decode the header of the token and return the header claims, without checking anything.
 *
 * No verification or authentication is done as part of this.
 *
 * This returns the jwt _header_ claims, not the jwt _body_ claims.
 */
export interface MinimalTokenHeaderClaims {
  alg: AsymmetricSigningAlgorithm;
  typ: 'JWT';
  kid?: string;
}
export const getUnauthedHeaderClaims = <C extends MinimalTokenHeaderClaims>({ token }: { token: string }): C => {
  verifyTokenShape({ token }); // guard clause to catch malformed "token" inputs
  const parts = token.split('.');
  const payload = JSON.parse(base64UrlDecode(parts[0]));
  return payload;
};
