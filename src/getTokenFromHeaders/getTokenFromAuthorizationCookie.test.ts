import { getTokenFromAuthorizationCookie } from './getTokenFromAuthorizationCookie';

const exampleToken = `__header__.__body__.__sig__`;

describe('getTokenFromAuthorizationCookie', () => {
  it('should return null if cookie header is not defined', () => {
    const headers = {};
    const token = getTokenFromAuthorizationCookie({ headers });
    expect(token).toEqual(null);
  });
  it('should not find the token in authorization cookie, if the authorization cookie was not defined', () => {
    const headers = {
      Cookie: `gaid=821`,
    };
    const token = getTokenFromAuthorizationCookie({ headers });
    expect(token).toEqual(null);
  });
  it('should be able to find token in authorization cookie', () => {
    const headers = {
      cookie: `authorization=${exampleToken}`,
    };
    const token = getTokenFromAuthorizationCookie({ headers });
    expect(token).toEqual(exampleToken);
  });
  it('should be able to find token in authorization cookie, even surrounded by other cookies', () => {
    const headers = {
      cookie: `name=value; authorization=${exampleToken}; name3=value3`,
    };
    const token = getTokenFromAuthorizationCookie({ headers });
    expect(token).toEqual(exampleToken);
  });
  it('should be able to find token in authorization cookie, even if its the last cookie', () => {
    const headers = {
      cookie: `name=value; authorization=${exampleToken}`,
    };
    const token = getTokenFromAuthorizationCookie({ headers });
    expect(token).toEqual(exampleToken);
  });
  it('should be able to find token in authorization cookie, even if its the first cookie', () => {
    const headers = {
      cookie: `authorization=${exampleToken}; name3=value3`,
    };
    const token = getTokenFromAuthorizationCookie({ headers });
    expect(token).toEqual(exampleToken);
  });
  it('should not be able to find token in authorization cookie, if the cookie name is capitalized the first cookie, since cookie names are case sensitive', () => {
    const headers = {
      cookie: `Authorization=${exampleToken}`,
    };
    const token = getTokenFromAuthorizationCookie({ headers });
    expect(token).toEqual(null);
  });
  it('should be able to find token in authorization cookie, even if the cookie header key is capitalized', () => {
    const headers = {
      Cookie: `authorization=${exampleToken}`,
    };
    const token = getTokenFromAuthorizationCookie({ headers });
    expect(token).toEqual(exampleToken);
  });
  it('should not find the token in authorization cookie, if the cookie name just has authorization as a suffix ', () => {
    const headers = {
      Cookie: `attackerauthorization=${exampleToken}`,
    };
    const token = getTokenFromAuthorizationCookie({ headers });
    expect(token).toEqual(null);
  });
  it('should not find the token in the authorization cookie, if what is in the authorization cookie is not a jwt', () => {
    const headers = {
      Cookie: `authorization=__NOT_A_JWT__`,
    };
    const token = getTokenFromAuthorizationCookie({ headers });
    expect(token).toEqual(null);
  });
});
