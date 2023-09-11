import { base64UrlEncode } from './base64Url/base64UrlEncode';
import { discoverPublicKeyFromAuthServerMetadata } from './discoverPublicKeyFromAuthServerMetadata/discoverPublicKeyFromAuthServerMetadata';
import { getSignedClaims } from './getSignedClaims';
import { JwtVerificationError } from './verification/JwtVerificationError';

const token = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjRkLjMyYjhiNTU0LTEyZjUtNGY5Yi05ZjE2LWIxM2UwYjUzMjAxOSJ9.eyJpc3MiOiJodHRwczovL29hdXRoLndob2Rpcy5pby8zMmI4YjU1NC0xMmY1LTRmOWItOWYxNi1iMTNlMGI1MzIwMTkiLCJkaXIiOiIzMmI4YjU1NC0xMmY1LTRmOWItOWYxNi1iMTNlMGI1MzIwMTkiLCJhdWQiOiJodHRwczovL2dpdGh1Yi5jb20vd2hvZGlzaW8vc2ltcGxlLWp3dC1hdXRoIiwic3ViIjoiYmVlZmJlZWYtYmVlZi1iZWVmLWJlZWYtYmVlZmJlZWZiZWVmIiwianRpIjoiYjE2MjNlM2ItNWNjYi00YmViLTllN2ItMjMyZTU1MmI3OGM3IiwiaWF0IjoxNjk0NDM2ODUxLCJuYmYiOjE2OTQ0MzY4NTEsImV4cCI6MTY5NDQzNjg1MSwidHRsIjoxNjk0NDM2ODUxfQ.c-_lC73QBTWEZ6GiF_J3xOWzCqHmNfH-wTEtdxkwpT7DjhhlZeYDuI5rlK0OA9byvHv8_RyrEu7uA54efIC3rN8iim9ZmxN8r3Jyyqr6XPoJixdRSekmJRHA34v_S5zCN-WJkaaVkmkL2SPkAn59nIWEHPFxtbDpOFP4w0qyNjf7bttg0B6neQeMcM_fUO5730cgXWkFfTpS3GWhaFZAqEn_dakBJlbuUgxMdR9TiOMCvjDj-74lKqkQpePWEWLikD_biHX1-Vyab2HlVNKWDfRxoHTdV0Xwox8RDCs1WF7wM4aT8s6RJSwCPYvhuP4oDjluVebuw_CxudHk_uMhYXucMRvpTm-ew92EhkjpfqXtGG1EVKRPnRfkhhNPOJsYro1VuXskP1ETIrgUAKUG5p-FXJmnjVWD5uqmDRGOfZ283Q7T7RezeIHWi6CQqFV0FHMMsbx1Lo6AYIicT3YNH_3xZN5P_KPZsxJQRBvHomkNhN_E0ls9l8gdy69RMGMxVMUO3I_0weuqDI_GqD0jTCMziiVSriUZQ3XHP9xwBCfS3PEOESmdrFKMgCHsAi2og-LK9L-q60uAXQQeCEGRG26YWCtm2gQD3IURlcSxXr2KcVfR83pcWYVE2L20ZNv7DJOrIThJuhHSla1vp_bqhUxLXr4iqbjwdgWuYvmKqio`;

describe('getSignedClaims', () => {
  it('should find that it can getSignedClaims for an authentic tokens signature', async () => {
    const publicKey = await discoverPublicKeyFromAuthServerMetadata({ token });
    await getSignedClaims({ token, publicKey });
  });
  it('should find that it does not getSignedClaims for a token that has been manipulated', async () => {
    const publicKey = await discoverPublicKeyFromAuthServerMetadata({ token });

    // maliciously modify the claims of a token
    const tokenParts = token.split('.');
    const tokenClaims = JSON.parse(
      Buffer.from(tokenParts[1]!, 'base64').toString('utf-8'),
    ); // decode and parse the claims
    const deceitfulClaims = { ...tokenClaims, sub: 'muahaha-any-user-i-want' }; // be evil and change the userUuid of the token
    const deceitfulClaimsPayload = base64UrlEncode(
      JSON.stringify(deceitfulClaims),
    );
    const tokenOfDeceit = [
      tokenParts[0],
      deceitfulClaimsPayload,
      tokenParts[2],
    ].join('.'); // rebuild the token

    // prove that the signature will not be verified
    try {
      await getSignedClaims({ token: tokenOfDeceit, publicKey });
    } catch (error) {
      expect(error).toBeInstanceOf(JwtVerificationError);
      expect(error.message).toContain('this JWT can not be trusted!');
      expect(error.message).toContain('signature is wrong');
    }
  });
});
