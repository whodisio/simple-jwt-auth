/**
 * Decode the header of the token and return the header claims, without checking anything.
 *
 * No verification or authentication is done as part of this.
 *
 * This returns the jwt _header_ claims, not the jwt _body_ claims.
 */
interface MinimalTokenHeaderClaims {
  alg: string;
  typ: string;
  kid?: string;
}
export const getUnauthedHeaderClaims = <C extends MinimalTokenHeaderClaims>({ token }: { token: string }): C => {
  const parts = token.split('.');
  const payload = JSON.parse(Buffer.from(parts[0], 'base64').toString('utf-8'));
  return payload;
};
