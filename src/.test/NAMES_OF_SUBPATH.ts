/**
 * .what = the runtime names `simple-jwt-auth/unauthed` exports: the decode-side contract
 * .why = one list for the linked and the tarball checks, so a change to the subpath is named once
 */
export const NAMES_OF_SUBPATH: string[] = [
  'SimpleJwtAuthError',
  'getUnauthedClaims',
  'getUnauthedHeaderClaims',
  'isJSONWebToken',
  'redactSignature',
];
