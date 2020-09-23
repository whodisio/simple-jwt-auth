export interface MinimalTokenClaims {
  iss: string;
  aud: string;
  sub: string;
  exp: number;
  nbf?: number;
}

/**
 * Decode the body of the token and return the claims, without checking authenticity of claims.
 *
 * This method is primarily used in client side applications, where no data should be trusted either way.
 *
 * In server side / backend applications, make sure to check the authenticity of the token's claims before trusting them first: use `getAuthedClaims` instead.
 */
export const getUnauthedClaims = <C extends MinimalTokenClaims>({ token }: { token: string }): C => {
  const parts = token.split('.');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf-8'));
  return payload;
};
