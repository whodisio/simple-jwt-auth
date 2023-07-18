import { castBase64ToBase64Url } from '../base64Url/castBase64ToBase64Url';
import { castJwtAlgToCryptoAlg } from './castJwtAlgToCryptoAlg';
import { importCrypto } from './importCrypto';

export const createVerifiableSignature = ({
  alg,
  payload,
  privateKey,
}: {
  alg: string;
  payload: string;
  privateKey: string;
}) => {
  const crypto = importCrypto();
  const cryptoAlg = castJwtAlgToCryptoAlg(alg);
  const signatureBuffer = crypto
    .createSign(cryptoAlg)
    .update(payload)
    .sign(privateKey);
  const signature = castBase64ToBase64Url(signatureBuffer.toString('base64'));
  return signature;
};
