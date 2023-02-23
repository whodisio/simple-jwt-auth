import crypto from 'crypto';

import { castBase64UrlToBase64 } from '../base64Url/castBase64UrlToBase64';
import { getUnauthedHeaderClaims } from '../getUnauthedHeaderClaims';
import { castJwtAlgToCryptoAlg } from './castJwtAlgToCryptoAlg';

/**
 * determines whether token's signature is verified
 *
 * i.e.,
 * - does the signature match the claims? (confirm claims)
 * - does the public key for the issuer match the signature? (confirm issuer)
 */
export const isSignatureVerified = ({
  token,
  publicKey,
}: {
  token: string;
  publicKey: string;
}) => {
  // convert the alg the token said it was signed by to an alg name that crypto understands
  const unauthedHeaderClaims = getUnauthedHeaderClaims({ token });
  const cryptoAlg = castJwtAlgToCryptoAlg(unauthedHeaderClaims.alg);

  // attempt to verify by using the signature
  const verificationInput = token.split('.').slice(0, 2).join('.'); // drop the signature
  const signatureClaim = token.split('.').slice(-1)[0]!; // signature is the last el
  const unescapedSignatureClaim = castBase64UrlToBase64(signatureClaim); // JWT's are url encoded, so that they are safe to pass in urls (i.e., base64URL format). crypto only supports normal base64, so we decode base64Url into base64 for interop
  const verified = crypto
    .createVerify(cryptoAlg)
    .update(verificationInput)
    .verify(publicKey, unescapedSignatureClaim, 'base64');

  // return the result
  return verified;
};
