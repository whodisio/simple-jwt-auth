import { SimpleJwtAuthError } from './SimpleJwtAuthError';
import { getPublicKey } from './getPublicKey/getPublicKey';
import { getSignedClaims } from './getSignedClaims';
import { MinimalTokenClaims } from './getUnauthedClaims';
import { verifyTokenIntent } from './verification/verifyTokenIntent';
import { verifyTokenShape } from './verification/verifyTokenShape';
import { verifyTokenTimestamps } from './verification/verifyTokenTimestamps';

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
  jwksUri,
}: {
  token: string;
  issuer: string;
  audience: string | string[];

  /**
   * the jwks uri at which the public key for this token can be found
   *
   * note
   * - for issuer's who support oauth2's discovery flow, this can be left blank, and the uri will be discovered (recommended)
   * - for issuer's who unable to support oauth2's discovery flow, this will need to be explicitly defined
   */
  jwksUri?: string;
}): Promise<C> => {
  // runtime validation: confirm and audiences were defined (everyone has types until they get punched in the runtime - mike tyson)
  if (!issuer)
    throw new SimpleJwtAuthError(
      'expected issuer must be defined for secure distributed jwt authentication',
    );
  if (!audience)
    throw new SimpleJwtAuthError(
      'expected audience must be defined for secure distributed jwt authentication',
    );
  const audiences = Array.isArray(audience) ? audience : [audience]; // normalize it to a more generic form in the process
  if (!audiences.length)
    throw new SimpleJwtAuthError(
      'at least one expected audience must be defined for secure distributed jwt authentication',
    );

  // check that the token has standard and expected shape
  await verifyTokenShape({ token });

  // check whether the audience and issuer of the token match, before even looking at verifying signature; critical for security in distributed system
  await verifyTokenIntent({
    token,
    intendedIssuer: issuer,
    intendedAudiences: audiences,
  });

  // check the timestamps to confirm the token is not expired
  await verifyTokenTimestamps({ token });

  // check that the token was signed correctly and safely; if so, grab claims
  const publicKey = await getPublicKey({ token, jwksUri });
  const signedClaims = await getSignedClaims<C>({ token, publicKey });

  // since the claims passed all of the checks above, they have now been authenticated
  return signedClaims;
};
