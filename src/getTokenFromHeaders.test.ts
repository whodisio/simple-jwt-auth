import { getTokenFromHeaders } from './getTokenFromHeaders';

describe('getTokenFromHeaders', () => {
  it('should return null if Authentication header is not defined', () => {
    const headers = {};
    const token = getTokenFromHeaders({ headers });
    expect(token).toEqual(null);
  });
  it('should return null if Authentication has a string that is not a token', () => {
    const headers = { Authentication: 'foobar' };
    const token = getTokenFromHeaders({ headers });
    expect(token).toEqual(null);
  });
  it('should return the token, removing the Bearer prefix', () => {
    const headers = { Authentication: 'Bearer __header__.__body__.__sig__' };
    const token = getTokenFromHeaders({ headers });
    expect(token).toEqual('__header__.__body__.__sig__');
  });
  it('should return the token, even if Bearer prefix was not used', () => {
    const headers = { Authentication: '__header__.__body__.__sig__' };
    const token = getTokenFromHeaders({ headers });
    expect(token).toEqual('__header__.__body__.__sig__');
  });
});
