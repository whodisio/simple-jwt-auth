import { base64UrlDecode } from './base64Url/base64UrlDecode';

export interface MinimalTokenClaims {
  iss: string;
  aud: string;
  sub: string;
  exp: number;
  nbf?: number;
}

/**
 * Decode the body of the token and return the claims, without checking authenticity of claims.
 */
export const getUnauthedClaims = <C extends MinimalTokenClaims>({ token }: { token: string }): C => {
  const parts = token.split('.');
  const payload = JSON.parse(base64UrlDecode(parts[1]));
  return payload;
};
