import { SimpleJwtAuthError } from '../SimpleJwtAuthError';
import { AsymmetricSigningAlgorithm } from './isAsymmetricSigningAlgorithm';

const JWT_ALG_TO_CRYPTO_ALG_MAP: Record<AsymmetricSigningAlgorithm, string> = {
  RS256: 'RSA-SHA256',
  RS384: 'RSA-SHA384',
  RS512: 'RSA-SHA512',
  ES256: 'SHA256',
  ES384: 'SHA384',
};

export const castJwtAlgToCryptoAlg = (
  alg: AsymmetricSigningAlgorithm,
): string => {
  const cryptoAlg = JWT_ALG_TO_CRYPTO_ALG_MAP[alg];
  if (!cryptoAlg) throw new SimpleJwtAuthError(`unsupported jwt alg: ${alg}`);
  return cryptoAlg;
};
