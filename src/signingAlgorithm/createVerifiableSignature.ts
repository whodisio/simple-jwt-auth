import crypto from 'crypto';

import { castBase64ToBase64Url } from '../base64Url/castBase64ToBase64Url';
import { MinimalTokenClaims } from '../getUnauthedClaims';
import { castJwtAlgToCryptoAlg } from './castJwtAlgToCryptoAlg';

export const createVerifiableSignature = <C extends MinimalTokenClaims>({
  alg,
  payload,
  privateKey,
}: {
  alg: string;
  payload: string;
  privateKey: string;
}) => {
  const cryptoAlg = castJwtAlgToCryptoAlg(alg);
  const signatureBuffer = crypto
    .createSign(cryptoAlg)
    .update(payload)
    .sign(privateKey);
  const signature = castBase64ToBase64Url(signatureBuffer.toString('base64'));
  return signature;
};
