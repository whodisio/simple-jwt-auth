import { castBase64ToBase64Url } from '@src/base64Url/castBase64ToBase64Url';
import { SimpleJwtAuthError } from '@src/SimpleJwtAuthError';

import { castJwtAlgToCryptoAlg } from './castJwtAlgToCryptoAlg';
import { getKeyTypeOfAlg } from './getKeyTypeOfAlg';
import { importCrypto } from './importCrypto';
import type { AsymmetricSigningAlgorithm } from './isAsymmetricSigningAlgorithm';
import { isEllipticSigningAlgorithm } from './isEllipticSigningAlgorithm';

/**
 * .what = signs a payload with a private key, under the given alg
 * .why = the signature segment of a jwt
 * .note = throws if the key type does not fit the alg: node would pick the mechanism
 *         from the key and emit a signature that does not match the token's `alg` header
 */
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

  // reject a key whose type does not fit the alg
  const keyTypeExpected = getKeyTypeOfAlg({ alg });
  const keyTypeFound = crypto.createPrivateKey(privateKey).asymmetricKeyType;
  if (keyTypeFound !== keyTypeExpected)
    throw new SimpleJwtAuthError(
      `private key type '${keyTypeFound}' does not fit alg '${alg}', which needs an '${keyTypeExpected}' key. sign with a key pair made for this alg, e.g., createSigningKeyPair('${alg}')`,
    );

  // sign the payload
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
