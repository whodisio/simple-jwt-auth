import { isJSONWebToken } from '../isJSONWebToken';
import { JwtVerificationError } from './JwtVerificationError';

/**
 * throw an error if token does not have proper shape
 *
 * protects the code against malformed input - but may also potentially protect against vulnerabilities
 */
export const verifyTokenShape = ({ token }: { token: string }) => {
  if (!isJSONWebToken(token)) throw new JwtVerificationError({ reason: 'token does not match shape of a JWT' });
};
