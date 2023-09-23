import { AsymmetricSigningAlgorithm } from './isAsymmetricSigningAlgorithm';

const ELLIPTIC_SIGNING_ALGORITHMS = ['ES256', 'ES384'] as const;
export type EllipticSigningAlgorithm =
  typeof ELLIPTIC_SIGNING_ALGORITHMS[number];
export const isEllipticSigningAlgorithm = (
  alg: AsymmetricSigningAlgorithm,
): alg is EllipticSigningAlgorithm =>
  ELLIPTIC_SIGNING_ALGORITHMS.includes(alg as any);
