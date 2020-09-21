/**
 * Decode the body of the token and return the claims, without checking anything.
 *
 * No verification or authentication is done as part of this. To check the authenticity of the token before returning the claims, use `getAuthedClaims` instead.
 */
export const getUnauthedClaims = ({ token }: { token: string }) => {
  const parts = token.split('.');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf-8'));
  return payload;
};
