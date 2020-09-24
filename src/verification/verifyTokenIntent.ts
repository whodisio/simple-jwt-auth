import { getUnauthedClaims } from '../getUnauthedClaims';
import { JwtVerificationError } from './JwtVerificationError';

/**
 * it is critical to security to check the intent of a token, not just that its well formed.
 *
 * specifically, it is critical to check that:
 * - the token is coming from the intended issuer
 * - the token is intended for your application
 *
 * if either of these things are not satisfied, then the token should not be trusted
 *
 * if either of these things are not verified, then your authentication strategy is vulnerable and could be maliciously abused by an attacker
 *
 * ref: https://www.cloudidentity.com/blog/2014/03/03/principles-of-token-validation/
 */
export const verifyTokenIntent = ({
  token,
  intendedIssuer,
  intendedAudiences,
}: {
  token: string;
  intendedIssuer: string;
  intendedAudiences: string[];
}) => {
  const unauthedClaims = getUnauthedClaims({ token });
  if (unauthedClaims.iss !== intendedIssuer)
    throw new JwtVerificationError({ reason: `token was issued by an unintended issuer: ${unauthedClaims.iss}` });
  if (!intendedAudiences.includes(unauthedClaims.aud))
    throw new JwtVerificationError({ reason: `token was issued to be used for an unintended audience: ${unauthedClaims.aud}` });
};
