import { MinimalTokenClaims } from './getUnauthedClaims';
import { SimpleJwtAuthError } from './SimpleJwtAuthError';
import { verifyTokenIntent } from './verification/verifyTokenIntent';
import { verifyTokenTimestamps } from './verification/verifyTokenTimestamps';
import { discoverPublicKeyFromAuthServerMetadata } from './discoverPublicKeyFromAuthServerMetadata/discoverPublicKeyFromAuthServerMetadata';
import { getSignedClaims } from './getSignedClaims';

/**
 * Authenticates the claims made by the JWT, conforming to highest security standards, before returning claims.
 *
 * Checks:
 * - that the token was issued by the expected issuer (prevents trusting malicious issuers)
 * - that the token was issued to be used by the expected audience (prevents trusting tokens issued for a different application to be hijacked used in yours)
 * - that the token is still valid based on timestamps (prevents having tokens that live forever - which are a greater risk if stolen)
 * - that an asymmetric signing algorithm was used (prevents accidental usage of symmetric signing algorithms in distributed setting)
 * - that the issuer really made these claims, by checking the signature (prevents malicious users from manipulating the claims in a token after its been issued)
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

  // check that the token was signed correctly and safely; if so, grab claims
  const publicKey = await discoverPublicKeyFromAuthServerMetadata({ token }); // grab the public key in a distributed fashion, w/ standard oauth discovery flow
  const signedClaims = await getSignedClaims<C>({ token, publicKey });

  // since the claims passed all of the checks above, they have now been authenticated
  return signedClaims;
};