import { isRedactedSignatureToken } from './isRedactedSignatureToken';
import { redactSignature } from './redactSignature';

const exampleValidTokenShape =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

describe('isRedactedSignatureToken', () => {
  it('should return true for a redacted signature token', () => {
    const isRedacted = isRedactedSignatureToken(redactSignature({ token: exampleValidTokenShape }));
    expect(isRedacted).toEqual(true);
  });
  it('should return false for non-redacted signature token', () => {
    const isRedacted = isRedactedSignatureToken(exampleValidTokenShape);
    expect(isRedacted).toEqual(false);
  });
});
