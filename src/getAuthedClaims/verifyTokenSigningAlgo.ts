import { getUnauthedHeaderClaims } from '../getUnauthedHeaderClaims';
import { isAsymmetricSigningAlgorithm } from '../signingAlgorithm/isAsymmetricSigningAlgorithm';
import { JwtAuthenticationError } from './JwtAuthenticationError';

/**
 * only asymmetric signing algorithms can be securely used in a distributed authentication strategy.
 *
 * why? symmetric signing algorithms do not have public keys, so third parties have no way of verifying the authenticity of a token - unless the private key is made public, in which case anyone can issue verifiable claims and the strategy is no longer secure.
 *
 * this library supports distributed authentication strategies, so symmetric keys are forbidden
 */
export const verifyTokenSigningAlgo = ({ token }: { token: string }) => {
  const unauthedHeaderClaims = getUnauthedHeaderClaims({ token });
  if (!isAsymmetricSigningAlgorithm(unauthedHeaderClaims.alg))
    throw new JwtAuthenticationError({
      reason: `tokens must be signed with asymmetric signing algorithms for secure distributed jwt authentication. found \`token.header.alg = ${unauthedHeaderClaims.alg}\` instead.`,
    });
};
