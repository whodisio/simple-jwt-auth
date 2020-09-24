import { verifyTokenSignature } from './verification/verifyTokenSignature';
import { getSignedClaims } from './getSignedClaims';
import { JwtVerificationError } from './verification/JwtVerificationError';

jest.mock('./verification/verifyTokenSignature');
const verifyTokenSignatureMock = verifyTokenSignature as jest.Mock;

describe('getSignedClaims', () => {
  describe('token signing algorithm', () => {
    it('should throw an error if user token specifies a symmetric signing algorithm - huge security risk otherwise since we lookup public key', async () => {
      const token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvLy4uLiIsImF1ZCI6ImU5MTMwNTMwLTEwNzItNDkxNS1hOGI5LTk3NDkwMGRiZWU1ZCIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MjcxNjIzOTAyMn0.36AlX4aah8RLz8jUCQzQ7H9EjHEUn6bjYU5_SEp8Psk`;
      try {
        await getSignedClaims({ token, publicKey: '__PUBLIC_KEY__' });
        throw new Error('should not reach here');
      } catch (error) {
        expect(error).toBeInstanceOf(JwtVerificationError);
        expect(error.message).toContain('this JWT can not be trusted!');
        expect(error.message).toContain('tokens must be signed with asymmetric signing algorithm');
      }
    });
  });
  describe('token signature', () => {
    it('should verify the token signature', async () => {
      const token = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvLy4uLiIsImF1ZCI6ImU5MTMwNTMwLTEwNzItNDkxNS1hOGI5LTk3NDkwMGRiZWU1ZCIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MjcxNjIzOTAyMn0.AySl0Ir00Unsa7rvhuqd37vYtIIL3SJ3DX5cUXm-v9RecNgsWeGj0iGgppHi-Dd_jrTsBSXUsxq__oMZTnhvtxzymXZzsKE5jvX484ZfbNp5dudRuvwZKwnm63NXK12hoszViPMId8v34M_kWGLg1lLDgvEsXRxKp5RnZ5VqzqFyU1oJDRB3eOHjyF6z1F_1zNdin0LgskdIK0TdWyBwP-iphCb3kLmgZ2m8JWK8a56oWWTjFwJTNwiYu8QogrxZO6d4xjcD4UstQ7hvrynLMPu3wgVLMp-jiC-rjuUnVUj-iucjyJVswDdlVaTZ_PbUdY4uVeIKxL496WTyuhBAQTjhgnNAthSdzbw7vjRLU_JOF5ifNLKdTTgtsLW_6gFb-ZQhIz2jd81bQWh36qOa901HAALgbxF9yGtyLnaty3YAvCO7zuiymxyAnSRx78f-461Xn0Lwo83sZREQ8p0cjJnrLJWLEX70ZP72TnUWhqn9IWILoKwhALh8E6bi0D7RaTCzd-pZnrnvOntTfKkHhy0KgvC8r57e4U8vZCgzAXlrgOMJBIldDA2mkQJswxlRvmLHyIruFeASGIfuQHI6-wd676T7bHgVyChcFVipJI_IvlaHjEqP2INzRdA2L0hijrOvQk0zA3e1kYkSFJMhzyrbVpGhdOcfVzHrMzadkOg`;
      await getSignedClaims({ token, publicKey: '__PUBLIC_KEY__' });
      expect(verifyTokenSignatureMock).toHaveBeenCalledTimes(1);
    });
  });
});
