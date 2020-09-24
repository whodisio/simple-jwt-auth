import crypto from 'crypto';

import { discoverPublicKeyFromAuthServerMetadata } from '../discoverPublicKeyFromAuthServerMetadata/discoverPublicKeyFromAuthServerMetadata';
import { getUnauthedHeaderClaims } from '../getUnauthedHeaderClaims';
import { JwtAuthenticationError } from './JwtAuthenticationError';
import { castJwtAlgToCryptoAlg } from '../signingAlgorithm/castJwtAlgToCryptoAlg';

const castBase64UrlToBase64 = (base64Url: string) => base64Url.replace(/-/g, '+').replace(/_/g, '/');

export const verifyTokenSignature = async ({ token }: { token: string }) => {
  // grab the public key in a distributed fashion, w/ standard oauth discovery flow
  const publicKey = await discoverPublicKeyFromAuthServerMetadata({ token });

  // convert the alg the token said it was signed by to an alg name that crypto understands
  const unauthedHeaderClaims = getUnauthedHeaderClaims({ token });
  const cryptoAlg = castJwtAlgToCryptoAlg(unauthedHeaderClaims.alg);

  // check that we can verify the signature
  const verificationInput = token.split('.').slice(0, 2).join('.'); // drop the signature
  const signatureClaim = token.split('.').slice(-1)[0]; // signature is the last el
  const unescapedSignatureClaim = castBase64UrlToBase64(signatureClaim); // JWT's are url encoded, so that they are safe to pass in urls (i.e., base64URL format). crypto only supports normal base64, so we decode base64Url into base64 for interop
  const verified = crypto.createVerify(cryptoAlg).update(verificationInput).verify(publicKey, unescapedSignatureClaim, 'base64');
  if (!verified) throw new JwtAuthenticationError({ reason: 'signature is incorrect' });
};
