import { discoverPublicKeyFromAuthServerMetadata } from './discoverPublicKeyFromAuthServerMetadata/discoverPublicKeyFromAuthServerMetadata';
import { createSecureDistributedAuthToken } from './createSecureDistributedAuthToken';
import { getAuthedClaims } from './getAuthedClaims';

const exampleKeys = {
  publicKey: `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArZjC17q0FaCN2Lojnb1a
LtnC3RVD2qs8f3Ylmk2nmHd4wUlMUUeWWuxrsmEmNJkriw+XLkNwEPo1/vgNidp8
VYwSUyhrF4TfazTccCQIhBOlsB2oA3J5vxUnSbqNpYabB/UdPIzPfqlAZaDhkc4a
AWJUT4sfB5xL/msgnyzC0gd1uf1/VoJokXW+TKj2QZhojElSvJ1AXlpaGWOGxH5a
VzYwtRKt/fu39ovhNSMcBfgqO71stY1/gnBeXSvuFiXCXaxy461llbNHpf2r7hXA
HqIX3pCCBFk/nsKAwBmt+pji5JuzZEJvDFagCFxF+a6O2fJ6D9qZqQskw9yC+/bB
RTFvuTND6RrXPw1U5baEUS6stWe99rAe4gDe5r6/1MD2HJ27hA0OG0mNjwdMp0VZ
QmfxTjYLIhDFWIEy9RL2A8GpHpfdQEfWHaCAehgEHYOWKR+yP65WCDexqQBcKxrI
rmeImiwMWcfqWXnyYncQ1bB2bHIYx1ZqrFM4zlk+oTH88nf7n6OvR9Cn2hPGUgaH
QnlQHTvGLRgRdOukmi4g05tw4gGtP/mOz4VO8K9VtKd2vLysL90pDeEzl3jCvJHT
KT+34+GEdkl1NxsEPZKuk387zZ5J6smokOR5yEk3weLo+kzAbnOl0zJ7ojw1l4iR
6vPHKcH95tkgCy0u94bMEUMCAwEAAQ==
-----END PUBLIC KEY-----
  `.trim(),
  privateKey: `
-----BEGIN PRIVATE KEY-----
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
mRT0FysAHcj299tOe3ttU0gFxsbloQ==
-----END PRIVATE KEY-----
  `.trim(),
};

// mock that we discover the real public key each time
jest.mock('./discoverPublicKeyFromAuthServerMetadata/discoverPublicKeyFromAuthServerMetadata');
const discoverPublicKeyFromAuthServerMetadataMock = discoverPublicKeyFromAuthServerMetadata as jest.Mock;
discoverPublicKeyFromAuthServerMetadataMock.mockReturnValue(exampleKeys.publicKey);

describe('createSecureToken', () => {
  it('should be able to create a token that we can later getAuthedClaims on', async () => {
    // create a token
    const token = createSecureDistributedAuthToken({
      headerClaims: { alg: 'RS256', kid: '4.some_directory', typ: 'JWT' },
      claims: {
        iss: 'https://auth.whodis.io/...',
        aud: '__some_directory__',
        sub: '__some_user__',
        exp: 2516239022,
      },
      privateKey: exampleKeys.privateKey,
    });
    expect(typeof token).toEqual('string'); // sanity check

    // check that we can auth on it, if the publicKey is discoverable
    const claims = await getAuthedClaims({ token, issuer: 'https://auth.whodis.io/...', audience: '__some_directory__' });
    expect(claims).toEqual({
      iss: 'https://auth.whodis.io/...',
      aud: '__some_directory__',
      sub: '__some_user__',
      exp: 2516239022,
    });
  });
});
