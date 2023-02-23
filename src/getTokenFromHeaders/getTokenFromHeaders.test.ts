import { getTokenFromAuthorizationCookieWithCSRFProtection } from './getTokenFromAuthorizationCookieWithCSRFProtection';
import { getTokenFromAuthorizationHeader } from './getTokenFromAuthorizationHeader';
import { getTokenFromHeaders } from './getTokenFromHeaders';

jest.mock('./getTokenFromAuthorizationCookieWithCSRFProtection');
const getTokenFromAuthorizationCookieWithCSRFProtectionMock =
  getTokenFromAuthorizationCookieWithCSRFProtection as jest.Mock;
getTokenFromAuthorizationCookieWithCSRFProtectionMock.mockReturnValue(null);

jest.mock('./getTokenFromAuthorizationHeader');
const getTokenFromAuthorizationHeaderMock =
  getTokenFromAuthorizationHeader as jest.Mock;
getTokenFromAuthorizationHeaderMock.mockReturnValue(null);

const exampleHeaders = '__EXAMPLE_HEADERS__' as any; // not a real object, since we mock out the things that actually look at it

describe('getTokenFromHeaders', () => {
  beforeEach(() => jest.resetAllMocks());
  it('should return the token from AuthCookie, if we found one - even if we could find one from AuthHeader', () => {
    getTokenFromAuthorizationCookieWithCSRFProtectionMock.mockReturnValueOnce(
      '__TOKEN_FROM_AUTH_COOKIE__',
    );
    getTokenFromAuthorizationHeaderMock.mockReturnValueOnce(
      '__TOKEN_FROM_AUTH_HEADER__',
    );
    const token = getTokenFromHeaders({ headers: exampleHeaders });
    expect(token).toEqual('__TOKEN_FROM_AUTH_COOKIE__');
  });
  it('should return the token from AuthHeader, if we found one but did not find one for AuthCookie', () => {
    getTokenFromAuthorizationCookieWithCSRFProtectionMock.mockReturnValueOnce(
      null,
    );
    getTokenFromAuthorizationHeaderMock.mockReturnValueOnce(
      '__TOKEN_FROM_AUTH_HEADER__',
    );
    const token = getTokenFromHeaders({ headers: exampleHeaders });
    expect(token).toEqual('__TOKEN_FROM_AUTH_HEADER__');
  });
  it('should return null if token was not found from both AuthCookie and AuthHeader', () => {
    getTokenFromAuthorizationCookieWithCSRFProtectionMock.mockReturnValueOnce(
      null,
    );
    getTokenFromAuthorizationHeaderMock.mockReturnValueOnce(null);
    const token = getTokenFromHeaders({ headers: exampleHeaders });
    expect(token).toEqual(null);
  });
});
