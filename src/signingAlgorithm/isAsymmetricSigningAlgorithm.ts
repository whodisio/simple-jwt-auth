const ASYMMETRIC_SIGNING_ALGORITHMS = ['RS256', 'RS384', 'RS512'] as const;
export type AsymmetricSigningAlgorithm =
  typeof ASYMMETRIC_SIGNING_ALGORITHMS[number];
export const isAsymmetricSigningAlgorithm = (
  alg: any,
): alg is AsymmetricSigningAlgorithm =>
  ASYMMETRIC_SIGNING_ALGORITHMS.includes(alg);
