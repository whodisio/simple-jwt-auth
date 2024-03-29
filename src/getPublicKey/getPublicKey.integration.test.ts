import { given, then } from 'test-fns';

import { getPublicKey } from './getPublicKey';

const token = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjRkLjMyYjhiNTU0LTEyZjUtNGY5Yi05ZjE2LWIxM2UwYjUzMjAxOSJ9.eyJpc3MiOiJodHRwczovL29hdXRoLndob2Rpcy5pby8zMmI4YjU1NC0xMmY1LTRmOWItOWYxNi1iMTNlMGI1MzIwMTkiLCJkaXIiOiIzMmI4YjU1NC0xMmY1LTRmOWItOWYxNi1iMTNlMGI1MzIwMTkiLCJhdWQiOiJodHRwczovL2dpdGh1Yi5jb20vd2hvZGlzaW8vc2ltcGxlLWp3dC1hdXRoIiwic3ViIjoiYmVlZmJlZWYtYmVlZi1iZWVmLWJlZWYtYmVlZmJlZWZiZWVmIiwianRpIjoiYjE2MjNlM2ItNWNjYi00YmViLTllN2ItMjMyZTU1MmI3OGM3IiwiaWF0IjoxNjk0NDM2ODUxLCJuYmYiOjE2OTQ0MzY4NTEsImV4cCI6MTY5NDQzNjg1MSwidHRsIjoxNjk0NDM2ODUxfQ.c-_lC73QBTWEZ6GiF_J3xOWzCqHmNfH-wTEtdxkwpT7DjhhlZeYDuI5rlK0OA9byvHv8_RyrEu7uA54efIC3rN8iim9ZmxN8r3Jyyqr6XPoJixdRSekmJRHA34v_S5zCN-WJkaaVkmkL2SPkAn59nIWEHPFxtbDpOFP4w0qyNjf7bttg0B6neQeMcM_fUO5730cgXWkFfTpS3GWhaFZAqEn_dakBJlbuUgxMdR9TiOMCvjDj-74lKqkQpePWEWLikD_biHX1-Vyab2HlVNKWDfRxoHTdV0Xwox8RDCs1WF7wM4aT8s6RJSwCPYvhuP4oDjluVebuw_CxudHk_uMhYXucMRvpTm-ew92EhkjpfqXtGG1EVKRPnRfkhhNPOJsYro1VuXskP1ETIrgUAKUG5p-FXJmnjVWD5uqmDRGOfZ283Q7T7RezeIHWi6CQqFV0FHMMsbx1Lo6AYIicT3YNH_3xZN5P_KPZsxJQRBvHomkNhN_E0ls9l8gdy69RMGMxVMUO3I_0weuqDI_GqD0jTCMziiVSriUZQ3XHP9xwBCfS3PEOESmdrFKMgCHsAi2og-LK9L-q60uAXQQeCEGRG26YWCtm2gQD3IURlcSxXr2KcVfR83pcWYVE2L20ZNv7DJOrIThJuhHSla1vp_bqhUxLXr4iqbjwdgWuYvmKqio`;

describe('getPublicKey', () => {
  given('the jwks uri needs to be discovered', () => {
    then(
      'it can discover public key from a reliable issuer (e.g., whodis.io)',
      async () => {
        const publicKey = await getPublicKey({ token });
        expect(publicKey).toContain('-----BEGIN PUBLIC KEY-----'); // sanity check
      },
    );
    then('it can get the public key from cache the second time', async () => {
      // this test is not necessary, but doesnt hurt.
      const publicKey = await getPublicKey({ token });
      const publicKeyAgain = await getPublicKey({
        token,
      });
      expect(publicKeyAgain).toContain(publicKey); // sanity check
    });
  });
  given('the jwks uri is explicitly defined', () => {
    const jwksUri =
      'https://oauth.whodis.io/32b8b554-12f5-4f9b-9f16-b13e0b532019/.well-known/jwks.json';
    then(
      `it can extract the public key from a reliable issuer's jwksUri (e.g., whodis.io)`,
      async () => {
        const publicKey = await getPublicKey({ token, jwksUri });
        expect(publicKey).toContain('-----BEGIN PUBLIC KEY-----'); // sanity check
      },
    );
    then('it can get the public key from cache the second time', async () => {
      // this test is not necessary, but doesnt hurt.
      const publicKey = await getPublicKey({ token, jwksUri });
      const publicKeyAgain = await getPublicKey({
        token,
      });
      expect(publicKeyAgain).toContain(publicKey); // sanity check
    });
  });
});
