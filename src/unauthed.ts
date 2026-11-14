/**
 * .what = the decode-side entry, `simple-jwt-auth/unauthed`
 * .why = a browser reads claims and redacts signatures, and needs none of the
 *        signature deps (jwk-to-pem, elliptic, asn1.js, axios, parse-domain, crypto).
 *        this entry reaches only the decode files, so a bundle sheds the rest
 * .note = re-exports the same modules as the root, so root and subpath share one
 *         class per error and one module per op. `unauthed.acceptance.test.ts`
 *         walks the built graph of this entry and fails on any dep outside `buffer`
 */
export type { MinimalTokenClaims } from './getUnauthedClaims';
export { getUnauthedClaims } from './getUnauthedClaims';
export type { MinimalTokenHeaderClaims } from './getUnauthedHeaderClaims';
export { getUnauthedHeaderClaims } from './getUnauthedHeaderClaims';
export { isJSONWebToken } from './isJSONWebToken';
export { redactSignature } from './redactSignature';
export { SimpleJwtAuthError } from './SimpleJwtAuthError';
