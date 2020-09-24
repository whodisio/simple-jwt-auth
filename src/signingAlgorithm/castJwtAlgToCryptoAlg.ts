import { SimpleJwtAuthError } from '../SimpleJwtAuthError';

const JWT_ALG_TO_CRYPTO_ALG_MAP: { [index: string]: string } = {
  RS256: 'RSA-SHA256',
  RS384: 'RSA-SHA384',
  RS512: 'RSA-SHA512',
};

export const castJwtAlgToCryptoAlg = (alg: string): string => {
  const cryptoAlg = JWT_ALG_TO_CRYPTO_ALG_MAP[alg];
  if (!cryptoAlg) throw new SimpleJwtAuthError(`unsupported jwt alg: ${alg}`);
  return cryptoAlg;
};
