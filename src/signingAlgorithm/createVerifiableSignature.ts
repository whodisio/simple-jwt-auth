import { castBase64ToBase64Url } from '../base64Url/castBase64ToBase64Url';
import { castJwtAlgToCryptoAlg } from './castJwtAlgToCryptoAlg';
import { importCrypto } from './importCrypto';
import { AsymmetricSigningAlgorithm } from './isAsymmetricSigningAlgorithm';
import { isEllipticSigningAlgorithm } from './isEllipticSigningAlgorithm';

export const createVerifiableSignature = ({
  alg,
  payload,
  privateKey,
}: {
  alg: AsymmetricSigningAlgorithm;
  payload: string;
  privateKey: string;
}) => {
  const crypto = importCrypto();
  const cryptoAlg = castJwtAlgToCryptoAlg(alg);
  const signatureBuffer = crypto
    .createSign(cryptoAlg)
    .update(payload)
    .sign({
      key: privateKey,
      dsaEncoding: isEllipticSigningAlgorithm(alg) ? 'ieee-p1363' : undefined, // if its an elliptic signing algorithm, we must specify the specific encoding format, since node defaults to DER while jwt's use IEEE; https://stackoverflow.com/questions/39499040/generating-ecdsa-signature-with-node-js-crypto?rq=3
    });
  const signature = castBase64ToBase64Url(signatureBuffer.toString('base64'));
  return signature;
};
