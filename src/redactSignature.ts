import { SimpleJwtAuthError } from './SimpleJwtAuthError';
import { isJSONWebToken } from './isJSONWebToken';

/**
 * a simple method which redacts the signature from a token to make it unauthenticatable - but still capable of having unauthed claims extracted
 *
 * this allows the claims of the token to be shared publicly and used in insecure and vulnerable environments (e.g., websites), without risking giving an attacker the ability to make authenticated requests with these claims (e.g., through XSS)
 */
export const redactSignature = ({ token }: { token: string }) => {
  if (!isJSONWebToken(token))
    throw new SimpleJwtAuthError('token does not match shape of a JWT');
  return [...token.split('.').slice(0, 2), '__REDACTED__'].join('.');
};
