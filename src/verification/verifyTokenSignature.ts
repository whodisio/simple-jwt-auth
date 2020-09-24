import { isSignatureVerified } from '../signingAlgorithm/isSignatureVerified';
import { JwtVerificationError } from './JwtVerificationError';

export const verifyTokenSignature = ({ token, publicKey }: { token: string; publicKey: string }) => {
  // determine if signature is verified
  const verified = isSignatureVerified({ token, publicKey });

  // throw an error if its not
  if (!verified) throw new JwtVerificationError({ reason: 'signature is wrong' });
};
