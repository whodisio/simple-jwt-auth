import { getAuthedClaims } from './getAuthedClaims';
import { JwtAuthenticationError } from './JwtAuthenticationError';
import { verifyTokenSignature } from './verifyTokenSignature';

jest.mock('./verifyTokenSignature');
const verifyTokenSignatureMock = verifyTokenSignature as jest.Mock;

describe('getAuthedClaims', () => {
  beforeEach(() => jest.clearAllMocks());
  describe('token intent', () => {
    it('should check the issuer of the token against the intended issuer', async () => {
      const token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Il9fa2V5X2lkX18ifQ.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvLy4uLiIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.AvXcwdU4amvp-eQwREHAQORKAbUe-crJuJoabABS_fE`;
      try {
        await getAuthedClaims({ token, issuer: 'not the same issuer', audience: '__AUDIENCE__' });
        throw new Error('should not reach here');
      } catch (error) {
        expect(error).toBeInstanceOf(JwtAuthenticationError);
        expect(error.message).toContain('this JWT can not be trusted!');
        expect(error.message).toContain('token was issued by an unintended issuer');
      }
    });
    it('should check the audience of the token against the intended audience', async () => {
      const token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvLy4uLiIsImF1ZCI6ImU5MTMwNTMwLTEwNzItNDkxNS1hOGI5LTk3NDkwMGRiZWU1ZCIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.M8rF3aCuWyXuvfJmfDzUiSdTFIiBTGbjTkgrnXTmX2k`;
      try {
        await getAuthedClaims({ token, issuer: 'https://auth.whodis.io/...', audience: 'not the right audience' });
        throw new Error('should not reach here');
      } catch (error) {
        expect(error).toBeInstanceOf(JwtAuthenticationError);
        expect(error.message).toContain('this JWT can not be trusted!');
        expect(error.message).toContain('token was issued to be used for an unintended audience');
      }
    });
  });
  describe('token timestamps', () => {
    it('should throw an error if no expiration is defined', async () => {
      const token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvLy4uLiIsImF1ZCI6ImU5MTMwNTMwLTEwNzItNDkxNS1hOGI5LTk3NDkwMGRiZWU1ZCIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.M8rF3aCuWyXuvfJmfDzUiSdTFIiBTGbjTkgrnXTmX2k`;
      try {
        await getAuthedClaims({ token, issuer: 'https://auth.whodis.io/...', audience: 'e9130530-1072-4915-a8b9-974900dbee5d' });
        throw new Error('should not reach here');
      } catch (error) {
        expect(error).toBeInstanceOf(JwtAuthenticationError);
        expect(error.message).toContain('this JWT can not be trusted!');
        expect(error.message).toContain('no expiration claim on the token. this is very unsafe');
      }
    });
    it('should throw an error if expiration has passed', async () => {
      const token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvLy4uLiIsImF1ZCI6ImU5MTMwNTMwLTEwNzItNDkxNS1hOGI5LTk3NDkwMGRiZWU1ZCIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjIzOTAyMn0.ivXS-95cx_WJbRHN89enW9TmAyKuRoXPu51D4XWUXFY`;
      try {
        await getAuthedClaims({ token, issuer: 'https://auth.whodis.io/...', audience: 'e9130530-1072-4915-a8b9-974900dbee5d' });
        throw new Error('should not reach here');
      } catch (error) {
        expect(error).toBeInstanceOf(JwtAuthenticationError);
        expect(error.message).toContain('this JWT can not be trusted!');
        expect(error.message).toContain('token has expired');
      }
    });
    it('should throw an error if nbf is defined and it has not passed yet', async () => {
      const token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvLy4uLiIsImF1ZCI6ImU5MTMwNTMwLTEwNzItNDkxNS1hOGI5LTk3NDkwMGRiZWU1ZCIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MjcxNjIzOTAyMiwibmJmIjoyNzE2MjM5MDIyfQ.qqHlH1yiSq9BFFXTQmuF8vWwBLyfLHQcFN_NxWBMseI`;
      try {
        await getAuthedClaims({ token, issuer: 'https://auth.whodis.io/...', audience: 'e9130530-1072-4915-a8b9-974900dbee5d' });
        throw new Error('should not reach here');
      } catch (error) {
        expect(error).toBeInstanceOf(JwtAuthenticationError);
        expect(error.message).toContain('this JWT can not be trusted!');
        expect(error.message).toContain('token can not be used yet');
      }
    });
  });
  describe('token signing algorithm', () => {
    it('should throw an error if user token specifies a symmetric signing algorithm - huge security risk otherwise since we lookup public key', async () => {
      const token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvLy4uLiIsImF1ZCI6ImU5MTMwNTMwLTEwNzItNDkxNS1hOGI5LTk3NDkwMGRiZWU1ZCIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MjcxNjIzOTAyMn0.36AlX4aah8RLz8jUCQzQ7H9EjHEUn6bjYU5_SEp8Psk`;
      try {
        await getAuthedClaims({ token, issuer: 'https://auth.whodis.io/...', audience: 'e9130530-1072-4915-a8b9-974900dbee5d' });
        throw new Error('should not reach here');
      } catch (error) {
        expect(error).toBeInstanceOf(JwtAuthenticationError);
        expect(error.message).toContain('this JWT can not be trusted!');
        expect(error.message).toContain('tokens must be signed with asymmetric signing algorithm');
      }
    });
  });
  describe('token signature', () => {
    it('should verify the token signature', async () => {
      const token = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvLy4uLiIsImF1ZCI6ImU5MTMwNTMwLTEwNzItNDkxNS1hOGI5LTk3NDkwMGRiZWU1ZCIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MjcxNjIzOTAyMn0.AySl0Ir00Unsa7rvhuqd37vYtIIL3SJ3DX5cUXm-v9RecNgsWeGj0iGgppHi-Dd_jrTsBSXUsxq__oMZTnhvtxzymXZzsKE5jvX484ZfbNp5dudRuvwZKwnm63NXK12hoszViPMId8v34M_kWGLg1lLDgvEsXRxKp5RnZ5VqzqFyU1oJDRB3eOHjyF6z1F_1zNdin0LgskdIK0TdWyBwP-iphCb3kLmgZ2m8JWK8a56oWWTjFwJTNwiYu8QogrxZO6d4xjcD4UstQ7hvrynLMPu3wgVLMp-jiC-rjuUnVUj-iucjyJVswDdlVaTZ_PbUdY4uVeIKxL496WTyuhBAQTjhgnNAthSdzbw7vjRLU_JOF5ifNLKdTTgtsLW_6gFb-ZQhIz2jd81bQWh36qOa901HAALgbxF9yGtyLnaty3YAvCO7zuiymxyAnSRx78f-461Xn0Lwo83sZREQ8p0cjJnrLJWLEX70ZP72TnUWhqn9IWILoKwhALh8E6bi0D7RaTCzd-pZnrnvOntTfKkHhy0KgvC8r57e4U8vZCgzAXlrgOMJBIldDA2mkQJswxlRvmLHyIruFeASGIfuQHI6-wd676T7bHgVyChcFVipJI_IvlaHjEqP2INzRdA2L0hijrOvQk0zA3e1kYkSFJMhzyrbVpGhdOcfVzHrMzadkOg`;
      await getAuthedClaims({ token, issuer: 'https://auth.whodis.io/...', audience: 'e9130530-1072-4915-a8b9-974900dbee5d' });
      expect(verifyTokenSignatureMock).toHaveBeenCalledTimes(1);
    });
  });
  describe('result', () => {
    it('should return claims if all was verified (i.e., token was authenticated)', async () => {
      const token = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGgud2hvZGlzLmlvLy4uLiIsImF1ZCI6ImU5MTMwNTMwLTEwNzItNDkxNS1hOGI5LTk3NDkwMGRiZWU1ZCIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MjcxNjIzOTAyMn0.AySl0Ir00Unsa7rvhuqd37vYtIIL3SJ3DX5cUXm-v9RecNgsWeGj0iGgppHi-Dd_jrTsBSXUsxq__oMZTnhvtxzymXZzsKE5jvX484ZfbNp5dudRuvwZKwnm63NXK12hoszViPMId8v34M_kWGLg1lLDgvEsXRxKp5RnZ5VqzqFyU1oJDRB3eOHjyF6z1F_1zNdin0LgskdIK0TdWyBwP-iphCb3kLmgZ2m8JWK8a56oWWTjFwJTNwiYu8QogrxZO6d4xjcD4UstQ7hvrynLMPu3wgVLMp-jiC-rjuUnVUj-iucjyJVswDdlVaTZ_PbUdY4uVeIKxL496WTyuhBAQTjhgnNAthSdzbw7vjRLU_JOF5ifNLKdTTgtsLW_6gFb-ZQhIz2jd81bQWh36qOa901HAALgbxF9yGtyLnaty3YAvCO7zuiymxyAnSRx78f-461Xn0Lwo83sZREQ8p0cjJnrLJWLEX70ZP72TnUWhqn9IWILoKwhALh8E6bi0D7RaTCzd-pZnrnvOntTfKkHhy0KgvC8r57e4U8vZCgzAXlrgOMJBIldDA2mkQJswxlRvmLHyIruFeASGIfuQHI6-wd676T7bHgVyChcFVipJI_IvlaHjEqP2INzRdA2L0hijrOvQk0zA3e1kYkSFJMhzyrbVpGhdOcfVzHrMzadkOg`;
      const claims = await getAuthedClaims({ token, issuer: 'https://auth.whodis.io/...', audience: 'e9130530-1072-4915-a8b9-974900dbee5d' });
      expect(claims).toEqual({
        iss: 'https://auth.whodis.io/...',
        aud: 'e9130530-1072-4915-a8b9-974900dbee5d',
        sub: '1234567890',
        name: 'John Doe',
        iat: 1516239022,
        exp: 2716239022,
      });
    });
  });
});
