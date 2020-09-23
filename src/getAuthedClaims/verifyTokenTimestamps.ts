import { fromUnixTime, isAfter, isBefore } from 'date-fns';

import { getUnauthedClaims } from '../getUnauthedClaims';
import { JwtAuthenticationError } from './JwtAuthenticationError';

export const verifyTokenTimestamps = ({ token }: { token: string }) => {
  const unauthedClaims = getUnauthedClaims({ token });
  const now = new Date();

  // check that the token has not expired
  if (!unauthedClaims.exp) throw new JwtAuthenticationError({ reason: 'no expiration claim on the token. this is very unsafe' });
  const hasExpired = isAfter(now, fromUnixTime(unauthedClaims.exp));
  if (hasExpired) throw new JwtAuthenticationError({ reason: 'token has expired (see `token.claims.exp`)' });

  // check that its not too early, if the token specified a "not before" timestamp
  if (unauthedClaims.nbf) {
    const isTooEarly = isBefore(now, fromUnixTime(unauthedClaims.nbf));
    if (isTooEarly) throw new JwtAuthenticationError({ reason: 'token can not be used yet (see `token.claims.nbf`)' });
  }
};
