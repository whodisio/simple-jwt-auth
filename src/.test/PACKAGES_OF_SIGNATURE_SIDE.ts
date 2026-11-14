/**
 * .what = the packages of the signature side, which the wish forbids in the decode-side graph
 * .why = one list for the clamp, the runtime load check, and the bundle check, so a new
 *        signature-side dep is named once
 * .note = node's `crypto` builtin is no package, so the clamp adds it to this list on its own
 */
export const PACKAGES_OF_SIGNATURE_SIDE: string[] = [
  'jwk-to-pem',
  'elliptic',
  'asn1.js',
  'axios',
  'parse-domain',
];
