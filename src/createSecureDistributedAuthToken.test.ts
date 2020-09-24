import { createSecureDistributedAuthToken } from './createSecureDistributedAuthToken';
import { SimpleJwtAuthError } from './SimpleJwtAuthError';

describe('createSecureDistributedAuthToken', () => {
  it('should require an asymmetric signing algorithm, since this is for distributed auth systems', async () => {
    try {
      createSecureDistributedAuthToken({
        headerClaims: { alg: 'HS256' as any, kid: '4.some_directory', typ: 'JWT' },
        claims: {
          iss: 'https://auth.whodis.io/...',
          aud: '__some_directory__',
          sub: '__some_user__',
          exp: 2516239022,
        },
        privateKey: '__PRIVATE_KEY__',
      });
    } catch (error) {
      expect(error).toBeInstanceOf(SimpleJwtAuthError);
      expect(error.message).toContain('only asymmetric signing algorithms are allowed in distributed systems');
    }
  });
  it('should require issuer to be defined', async () => {
    try {
      createSecureDistributedAuthToken({
        headerClaims: { alg: 'RS256' as any, kid: '4.some_directory', typ: 'JWT' },
        claims: {
          aud: '__some_directory__',
          sub: '__some_user__',
          exp: 2516239022,
        } as any,
        privateKey: '__PRIVATE_KEY__',
      });
    } catch (error) {
      expect(error).toBeInstanceOf(SimpleJwtAuthError);
      expect(error.message).toContain('token.claims.iss must be defined when creating a secure token');
    }
  });
  it('should require audience to be defined', async () => {
    try {
      createSecureDistributedAuthToken({
        headerClaims: { alg: 'RS256' as any, kid: '4.some_directory', typ: 'JWT' },
        claims: {
          iss: 'https://auth.whodis.io/...',
          sub: '__some_user__',
          exp: 2516239022,
        } as any,
        privateKey: '__PRIVATE_KEY__',
      });
    } catch (error) {
      expect(error).toBeInstanceOf(SimpleJwtAuthError);
      expect(error.message).toContain('token.claims.aud must be defined when creating a secure token');
    }
  });
  it('should require expiration to be defined', async () => {
    try {
      createSecureDistributedAuthToken({
        headerClaims: { alg: 'RS256' as any, kid: '4.some_directory', typ: 'JWT' },
        claims: {
          iss: 'https://auth.whodis.io/...',
          aud: '__some_directory__',
          sub: '__some_user__',
        } as any,
        privateKey: '__PRIVATE_KEY__',
      });
    } catch (error) {
      expect(error).toBeInstanceOf(SimpleJwtAuthError);
      expect(error.message).toContain('token.claims.exp must be defined when creating a secure token');
    }
  });
});
