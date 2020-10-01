import { getTokenFromHeaders } from './getTokenFromHeaders';

describe('getTokenFromHeaders', () => {
  it('should return null if Authorization header is not defined', () => {
    const headers = {};
    const token = getTokenFromHeaders({ headers });
    expect(token).toEqual(null);
  });
  it('should return null if Authorization has a string that is not a token', () => {
    const headers = { Authorization: 'foobar' };
    const token = getTokenFromHeaders({ headers });
    expect(token).toEqual(null);
  });
  it('should return the token, removing the Bearer prefix', () => {
    const headers = { Authorization: 'Bearer __header__.__body__.__sig__' };
    const token = getTokenFromHeaders({ headers });
    expect(token).toEqual('__header__.__body__.__sig__');
  });
  it('should return the token, even if header was lowercase', () => {
    const headers = { authorization: 'Bearer __header__.__body__.__sig__' };
    const token = getTokenFromHeaders({ headers });
    expect(token).toEqual('__header__.__body__.__sig__');
  });
  it('should return the token, even if Bearer prefix was not used', () => {
    const headers = { Authorization: '__header__.__body__.__sig__' };
    const token = getTokenFromHeaders({ headers });
    expect(token).toEqual('__header__.__body__.__sig__');
  });
});
