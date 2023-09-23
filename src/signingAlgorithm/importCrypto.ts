import type crypto from 'crypto';

/**
 * a method that safely imports the crypto utility in all environments
 *
 * usecases
 * - prevents react-native's metro bundler from throwing an error while proactively fetching all dependencies
 *   - it specifically requires the import to be within a try-catch to not throw its own error
 *   - ref: https://github.com/react-native-community/discussions-and-proposals/issues/120
 *
 * todo
 * - if there's a usecase for client side token creation or verification, use crypto-js or expo-crypto
 */
export const importCrypto = (): typeof crypto => {
  try {
    return require('crypto');
  } catch {
    throw new Error(
      'could not import crypto for isSignatureVerified. is this running in node.js?',
    );
  }
};
