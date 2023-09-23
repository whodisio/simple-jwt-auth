import { getUnauthedHeaderClaims } from '../getUnauthedHeaderClaims';
import { isSignatureVerified } from '../signingAlgorithm/isSignatureVerified';
import { JwtVerificationError } from './JwtVerificationError';

/**
 * asserts that a token's signature is verified for its claims
 */
export const verifyTokenSignature = ({
  token,
  publicKey,
}: {
  token: string;
  publicKey: string;
}) => {
  // determine if signature is verified
  const { alg } = getUnauthedHeaderClaims({ token });
  const payload = token.split('.').slice(0, 2).join('.'); // drop the signature
  const signature = token.split('.').slice(-1)[0]!; // signature is the last el
  const verified = isSignatureVerified({ alg, signature, payload, publicKey });

  // throw an error if its not
  if (!verified)
    throw new JwtVerificationError({ reason: 'signature is wrong' });
};
