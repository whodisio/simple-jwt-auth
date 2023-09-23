import { UnexpectedCodePathError } from '@ehmpathy/error-fns';

import { importCrypto } from './importCrypto';
import { AsymmetricSigningAlgorithm } from './isAsymmetricSigningAlgorithm';
import {
  EllipticSigningAlgorithm,
  isEllipticSigningAlgorithm,
} from './isEllipticSigningAlgorithm';

/**
 * defines the name of the curve to use for the given elliptic signing algo
 *
 * note
 * - valid options come from the node version's respective openssl library:  https://github.com/nodejs/node/blob/v15.12.0/deps/openssl/openssl/crypto/ec/ec_curve.c#L3163
 */
const ELLIPTIC_SIGNING_ALGORITHM_TO_CURVE_NAME_REGISTRY: Record<
  EllipticSigningAlgorithm,
  string
> = {
  ES256: 'P-256',
  ES384: 'P-384',
};

/**
 * method which creates a signing key pair for the given signing algorithm
 */
export const createSigningKeyPair = async (
  alg: AsymmetricSigningAlgorithm,
): Promise<{ format: 'pem'; privateKey: string; publicKey: string }> => {
  // grab the crypto module
  const crypto = await importCrypto();

  // support elliptical signing algorithms
  if (isEllipticSigningAlgorithm(alg)) {
    const { publicKey, privateKey } = await new Promise<{
      privateKey: string;
      publicKey: string;
    }>((resolve, reject) =>
      crypto.generateKeyPair(
        'ec',
        {
          namedCurve: ELLIPTIC_SIGNING_ALGORITHM_TO_CURVE_NAME_REGISTRY[alg],
          publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
          },
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
          },
        },
        (error, thisPublicKey, thisPrivateKey) =>
          error
            ? reject(error)
            : resolve({ publicKey: thisPublicKey, privateKey: thisPrivateKey }),
      ),
    );
    return {
      format: 'pem',
      publicKey,
      privateKey,
    };
  }

  // support rsa signing algorithms
  if (alg.startsWith('RS')) {
    const { publicKey, privateKey } = await new Promise<{
      privateKey: string;
      publicKey: string;
    }>((resolve, reject) =>
      crypto.generateKeyPair(
        'rsa',
        {
          modulusLength: 2048,
          publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
          },
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
          },
        },
        (error, thisPublicKey, thisPrivateKey) =>
          error
            ? reject(error)
            : resolve({ publicKey: thisPublicKey, privateKey: thisPrivateKey }),
      ),
    );
    return {
      format: 'pem',
      publicKey,
      privateKey,
    };
  }

  // otherwise, unexpected algo
  throw new UnexpectedCodePathError('unsupported algorithm specified', { alg });
};
