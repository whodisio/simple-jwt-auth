import type { AsymmetricSigningAlgorithm } from './isAsymmetricSigningAlgorithm';
import { isEllipticSigningAlgorithm } from './isEllipticSigningAlgorithm';

/**
 * .what = the key type an alg must be signed with, as node's `asymmetricKeyType` names it
 * .why = node picks the sign mechanism from the key, not the alg; a check against this
 *        keeps a token's `alg` header true to how it was signed
 */
export const getKeyTypeOfAlg = (input: {
  alg: AsymmetricSigningAlgorithm;
}): 'rsa' | 'ec' => (isEllipticSigningAlgorithm(input.alg) ? 'ec' : 'rsa');
