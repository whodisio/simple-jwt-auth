import { verifyTokenSignature } from './verifyTokenSignature';
import { JwtAuthenticationError } from './JwtAuthenticationError';

describe('verifyTokenSignature', () => {
  it('should find that it can verify an authentic tokens signature', async () => {
    const token = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjRkLmM3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiJ9.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvL2M3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiIsInN1YiI6ImJlZWZiZWVmLWJlZWYtYmVlZi1iZWVmLWJlZWZiZWVmYmVlZiIsImF1ZCI6ImM3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiIsImlhdCI6MTYwMDYyNTMzNiwibmJmIjoxNjAwNjI1MzM2LCJleHAiOjE2MDA2Njg1MzYsInR0bCI6MTYwMTkyMTMzNn0.F58A0ARfGujb7n5KMCwcbbwPh7UcH50y6ohWDzEIJRbkMoqvfZpyn6D8xrK_hyOtM54wP7UUJrtEK-XzfzzwyvZ9EYIWEhBZhHbHWqpYTEgxvM9gDaGgvqtuc5CuManfwONZh9ETxnVjY-NaigmIjpOog8C08wQ9e_DADJsdEmtdb_y0HWBuIo1lKOwdLFfEF7RJ-9ZZ415u_MCNjxhvn4CykQBIB92LYlfnbU6MpzeMo1QG7Tt3X8J_pbsTz4TsGD58vQHq01ibp8MXSZ-KoxE7Vs5BYS7o0-vU7yhkpH1TuoapUmWBI8ZFaOr-ym8E5iBvu-xn3Ms20PFigxiyzHddm9r2Z2MWiffYPhC8xHbM1IL3kSin-2wK7_3EdQT1X7_V8mk6ZJXaqBtvtL0nAx8Zf5JBcgj-mKbPQMtUM2aneHKU7rf5BFX9F-MfJhczn5ZiowmQOJruKOsPQRHNeR87VZprD_aDP6Q_5LcklCJoz3Ol-n3I-2YccCGgwilHF7bDlv4fGQlXXdZEDDYZwdA8U_SvuxPhowPqlOheeERgBjbxdodLHOgBfMR1hsvAqOmedOVCUREM3fiN7-iA3KdStpS6C2-_NHHGUwOlc1dCgbHYMLpJ565k98drCzancl3-Od5i6B5JqaFh7_n7-34R0s0sph9fkGoznVF4ZJM`;
    await verifyTokenSignature({ token });
  });
  it('should find that it does not verify a token that has been manipulated', async () => {
    // maliciously modify the claims of a token
    const token = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjRkLmM3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiJ9.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvL2M3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiIsInN1YiI6ImJlZWZiZWVmLWJlZWYtYmVlZi1iZWVmLWJlZWZiZWVmYmVlZiIsImF1ZCI6ImM3MWI4ZmQxLWJiYTctNDdlZS05NjZiLTY1YWI4NWIzNDk3MiIsImlhdCI6MTYwMDYyNTMzNiwibmJmIjoxNjAwNjI1MzM2LCJleHAiOjE2MDA2Njg1MzYsInR0bCI6MTYwMTkyMTMzNn0.F58A0ARfGujb7n5KMCwcbbwPh7UcH50y6ohWDzEIJRbkMoqvfZpyn6D8xrK_hyOtM54wP7UUJrtEK-XzfzzwyvZ9EYIWEhBZhHbHWqpYTEgxvM9gDaGgvqtuc5CuManfwONZh9ETxnVjY-NaigmIjpOog8C08wQ9e_DADJsdEmtdb_y0HWBuIo1lKOwdLFfEF7RJ-9ZZ415u_MCNjxhvn4CykQBIB92LYlfnbU6MpzeMo1QG7Tt3X8J_pbsTz4TsGD58vQHq01ibp8MXSZ-KoxE7Vs5BYS7o0-vU7yhkpH1TuoapUmWBI8ZFaOr-ym8E5iBvu-xn3Ms20PFigxiyzHddm9r2Z2MWiffYPhC8xHbM1IL3kSin-2wK7_3EdQT1X7_V8mk6ZJXaqBtvtL0nAx8Zf5JBcgj-mKbPQMtUM2aneHKU7rf5BFX9F-MfJhczn5ZiowmQOJruKOsPQRHNeR87VZprD_aDP6Q_5LcklCJoz3Ol-n3I-2YccCGgwilHF7bDlv4fGQlXXdZEDDYZwdA8U_SvuxPhowPqlOheeERgBjbxdodLHOgBfMR1hsvAqOmedOVCUREM3fiN7-iA3KdStpS6C2-_NHHGUwOlc1dCgbHYMLpJ565k98drCzancl3-Od5i6B5JqaFh7_n7-34R0s0sph9fkGoznVF4ZJM`;
    const tokenParts = token.split('.');
    const tokenClaims = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString('utf-8')); // decode and parse the claims
    const deceitfulClaims = { ...tokenClaims, sub: 'muahaha-any-user-i-want' }; // be evil and change the userUuid of the token
    const deceitfulClaimsPayload = Buffer.from(JSON.stringify(deceitfulClaims), 'utf-8').toString('base64').replace(/=/g, ''); // cast to base64Url (i.e., replace `=` to cast back)
    const tokenOfDeceit = [tokenParts[0], deceitfulClaimsPayload, tokenParts[2]].join('.'); // rebuild the token

    // prove that the signature will not be verified
    try {
      await verifyTokenSignature({ token: tokenOfDeceit });
    } catch (error) {
      expect(error).toBeInstanceOf(JwtAuthenticationError);
      expect(error.message).toContain('this JWT can not be trusted!');
      expect(error.message).toContain('signature is incorrect');
    }
  });
});
