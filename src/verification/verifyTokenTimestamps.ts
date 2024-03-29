import { getUnauthedClaims } from '../getUnauthedClaims';
import { fromUnixTime, isBefore, isExpiredToken } from '../isExpiredToken';
import { JwtVerificationError } from './JwtVerificationError';

export const verifyTokenTimestamps = ({ token }: { token: string }) => {
  const unauthedClaims = getUnauthedClaims({ token });
  const now = new Date();

  // check that the token has not expired
  if (!unauthedClaims.exp)
    throw new JwtVerificationError({
      reason: 'no expiration claim on the token. this is very unsafe',
    });
  const hasExpired = isExpiredToken(token); // note: we moved "isExpiredToken" logic out since it is a common usecase by callers of the package
  if (hasExpired)
    throw new JwtVerificationError({
      reason: 'token has expired (see `token.claims.exp`)',
    });

  // check that its not too early, if the token specified a "not before" timestamp
  if (unauthedClaims.nbf) {
    const isTooEarly = isBefore(now, fromUnixTime(unauthedClaims.nbf));
    if (isTooEarly)
      throw new JwtVerificationError({
        reason: 'token can not be used yet (see `token.claims.nbf`)',
      });
  }
};
