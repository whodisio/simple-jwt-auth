import { MinimalTokenClaims, getUnauthedClaims } from '../getUnauthedClaims';
import { SimpleJwtAuthError } from '../SimpleJwtAuthError';
import { verifyTokenIntent } from './verifyTokenIntent';
import { verifyTokenSigningAlgo } from './verifyTokenSigningAlgo';
import { verifyTokenTimestamps } from './verifyTokenTimestamps';
import { verifyTokenSignature } from './verifyTokenSignature';

/**
 * Authenticates the claims made by the JWT, conforming to highest security standards, before returning claims.
 *
 * This method is primarily used in server side / backend applications, where we must trust the data we are working with.
 *
 * In client side / frontend applications, there is no reason to authenticate claims as no data on frontend should be trusted anyway: use `getUnauthedClaims` instead.
 */
export const getAuthedClaims = async <C extends MinimalTokenClaims>({
  token,
  issuer,
  audience,
}: {
  token: string;
  issuer: string;
  audience: string | string[];
}): Promise<C> => {
  // runtime validation: confirm and audiences were defined (everyone has types until they get punched in the runtime - mike tyson)
  if (!issuer) throw new SimpleJwtAuthError('expected issuer must be defined for secure distributed jwt authentication');
  if (!audience) throw new SimpleJwtAuthError('expected audience must be defined for secure distributed jwt authentication');
  const audiences = Array.isArray(audience) ? audience : [audience]; // normalize it to a more generic form in the process
  if (!audiences.length) throw new SimpleJwtAuthError('at least one expected audience must be defined for secure distributed jwt authentication');

  // check whether the audience and issuer of the token match, before even looking at verifying signature; critical for security in distributed system
  await verifyTokenIntent({ token, intendedIssuer: issuer, intendedAudiences: audiences });

  // check the timestamps to confirm the token is not expired
  await verifyTokenTimestamps({ token });

  // check that the token was signed by an asymmetric algorithm - otherwise, this token can't be used securely in a distributed system. (i.e., there is no "publicKey" in a symmetric signing algo)
  await verifyTokenSigningAlgo({ token });

  // verify that the token was signed by the issuer
  await verifyTokenSignature({ token });

  // return the claims of the token, as with the above checks we have authenticated those claims
  const tokenClaims = getUnauthedClaims<C>({ token });
  return tokenClaims; // they are now authed
};
