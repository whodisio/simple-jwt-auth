import { getUnauthedClaims, MinimalTokenClaims } from './getUnauthedClaims';
import { verifyTokenSignature } from './verification/verifyTokenSignature';
import { verifyTokenSigningAlgo } from './verification/verifyTokenSigningAlgo';

/**
 * Simply check that the token was signed correctly, without checking anything else, and return the claims if so.
 *
 * NOTE: this does _not_ mean that the token should be trusted. All this confirms is that some server, somewhere, at some point in time, signed these claims. This token could still be from a malicious auth server, issued for a different application, or issued years ago - stolen - and no longer valid.
 *
 * Use `getAuthedClaims` in settings where you must trust the claims of a token.
 */
export const getSignedClaims = <C extends MinimalTokenClaims>({ token, publicKey }: { token: string; publicKey: string }): C => {
  // check that the token was signed by an asymmetric algorithm - otherwise, this token can't be used securely in a distributed system. (i.e., there is no "publicKey" in a symmetric signing algo)
  verifyTokenSigningAlgo({ token });

  // verify that the token was signed by the issuer
  verifyTokenSignature({ token, publicKey });

  // return the claims of the token, as with the above checks we have authenticated those claims
  const tokenClaims = getUnauthedClaims<C>({ token });
  return tokenClaims; // they are now authed
};
