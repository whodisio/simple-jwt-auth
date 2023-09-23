import { castBase64UrlToBase64 } from '../base64Url/castBase64UrlToBase64';
import { castJwtAlgToCryptoAlg } from './castJwtAlgToCryptoAlg';
import { importCrypto } from './importCrypto';
import { AsymmetricSigningAlgorithm } from './isAsymmetricSigningAlgorithm';
import { isEllipticSigningAlgorithm } from './isEllipticSigningAlgorithm';

/**
 * determines whether a signature can be verified for a given payload and public key
 */
export const isSignatureVerified = ({
  alg,
  signature,
  payload,
  publicKey,
}: {
  alg: AsymmetricSigningAlgorithm;
  signature: string;
  payload: string;
  publicKey: string;
}) => {
  const crypto = importCrypto();

  // convert the alg the token said it was signed by to an alg name that crypto understands
  const cryptoAlg = castJwtAlgToCryptoAlg(alg);

  // attempt to verify by using the signature
  const unescapedSignatureClaim = castBase64UrlToBase64(signature); // JWT's are url encoded, so that they are safe to pass in urls (i.e., base64URL format). crypto only supports normal base64, so we decode base64Url into base64 for interop
  const verified = crypto
    .createVerify(cryptoAlg)
    .update(payload)
    .verify(
      {
        key: publicKey,
        dsaEncoding: isEllipticSigningAlgorithm(alg) ? 'ieee-p1363' : undefined, // if its an elliptic signing algorithm, we must specify the specific encoding format, since node defaults to DER while jwt's use IEEE; https://stackoverflow.com/questions/39499040/generating-ecdsa-signature-with-node-js-crypto?rq=3
      },
      unescapedSignatureClaim,
      'base64',
    );

  // return the result
  return verified;
};
