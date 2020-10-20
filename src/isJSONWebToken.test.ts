import { castBase64UrlToBase64 } from './base64Url/castBase64UrlToBase64';
import { isJSONWebToken } from './isJSONWebToken';
import { redactSignature } from './redactSignature';

const exampleValidTokenShape =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

describe('isJSONWebToken', () => {
  it('should return true for a valid token', () => {
    const isJwt = isJSONWebToken(exampleValidTokenShape);
    expect(isJwt).toEqual(true);
  });
  it('should return false for gibberish', () => {
    const isJwt = isJSONWebToken('__TOKEN__');
    expect(isJwt).toEqual(false);
  });
  it('should return false if not base64Url encoded', () => {
    const base64Token = exampleValidTokenShape
      .split('.')
      .map((part) => castBase64UrlToBase64(part)) // decode each part
      .join('.');
    const isJwt = isJSONWebToken(base64Token);
    expect(isJwt).toEqual(false);
  });
  it('should return true even if signature is redacted', () => {
    const exampleTokenWithRedactedSignature = redactSignature({ token: exampleValidTokenShape });
    const isJwt = isJSONWebToken(exampleTokenWithRedactedSignature);
    expect(isJwt).toEqual(true);
  });
});
