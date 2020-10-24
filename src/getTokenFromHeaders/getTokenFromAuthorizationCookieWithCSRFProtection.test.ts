import { redactSignature } from '../redactSignature';
import { getTokenFromAuthorizationCookieWithCSRFProtection } from './getTokenFromAuthorizationCookieWithCSRFProtection';
import { PotentialCSRFAttackError } from './PotentialCSRFAttackError';
import { PotentialCSRFVulnerabilityError } from './PotentialCSRFVulnerabilityError';
import { PotentialXSSVulnerabilityError } from './PotentialXSSVulnerabilityError';

const exampleToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJmNWY3N2JjMC1iZTkwLTRmNGEtYmUyNS0wMThjYjUwZjBmMGEiLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiaHR0cHM6Ly9hcGkud2hvZGlzLmlvIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.M_-_WjXeURe5M7JplujTq2Bl1V-MTm-Gxy9-DN4Qr8Q`;
const exampleAntiCSRFToken = redactSignature({ token: exampleToken });

describe('getTokenFromAuthorizationCookieWithCSRFProtection', () => {
  it('should not get the token from the cookie, if cookie is not set', () => {
    const headers = {};
    const token = getTokenFromAuthorizationCookieWithCSRFProtection({ headers });
    expect(token).toEqual(null);
  });
  it('should be able to get token from cookie, if it includes the anti-csrf-token in the request and is from same site origin', () => {
    const headers = {
      cookie: `authorization=${exampleToken}`,
      authorization: `Bearer ${exampleAntiCSRFToken}`,
      origin: `https://www.whodis.io`, // audience is `https://api.whodis.io`, so these are same sit
    };
    const token = getTokenFromAuthorizationCookieWithCSRFProtection({ headers });
    expect(token).toEqual(exampleToken);
  });
  describe('Verifying Origin with Standard Headers', () => {
    it('should throw a CSRFAttemptError if the headers.origin is different from target origin', () => {
      const headers = {
        cookie: `authorization=${exampleToken}`,
        authorization: `Bearer ${exampleAntiCSRFToken}`,
        origin: `https://hakrsite.com`, // target origin of token is `https://api.whodis.io`, so this is different target
      };
      try {
        getTokenFromAuthorizationCookieWithCSRFProtection({ headers });
      } catch (error) {
        expect(error).toBeInstanceOf(PotentialCSRFAttackError);
        expect(error.message).toEqual(
          `Potential cross-site-request-forgery attack detected!!! source origin is not same site as target origin! (target='https://api.whodis.io', source='https://hakrsite.com')`,
        );
      }
    });
    it('should be able to get token from cookie, if headers.origin is the same as target origin', () => {
      const headers = {
        cookie: `authorization=${exampleToken}`,
        authorization: `Bearer ${exampleAntiCSRFToken}`,
        origin: `https://www.whodis.io`, // audience is `https://api.whodis.io`, so these are same site
      };
      const token = getTokenFromAuthorizationCookieWithCSRFProtection({ headers });
      expect(token).toEqual(exampleToken);
    });
    it('should throw a CSRFAttemptError if the headers.origin not set, and headers.referrer is different from target origin', () => {
      const headers = {
        cookie: `authorization=${exampleToken}`,
        authorization: `Bearer ${exampleAntiCSRFToken}`,
        referrer: `https://hakrsite.com`, // target origin of token is `https://api.whodis.io`, so this is different target
      };
      try {
        getTokenFromAuthorizationCookieWithCSRFProtection({ headers });
      } catch (error) {
        expect(error).toBeInstanceOf(PotentialCSRFAttackError);
        expect(error.message).toEqual(
          `Potential cross-site-request-forgery attack detected!!! source origin is not same site as target origin! (target='https://api.whodis.io', source='https://hakrsite.com')`,
        );
      }
    });
    it('should be able to get token from cookie, if headers.origin not set but headers.referrer is the same as target origin', () => {
      const headers = {
        cookie: `authorization=${exampleToken}`,
        authorization: `Bearer ${exampleAntiCSRFToken}`,
        referrer: `https://www.whodis.io`, // audience is `https://api.whodis.io`, so these are same site
      };
      const token = getTokenFromAuthorizationCookieWithCSRFProtection({ headers });
      expect(token).toEqual(exampleToken);
    });
    it('should throw a CSRFAttemptError if neither header.origins nor header.referrer is set', () => {
      const headers = {
        cookie: `authorization=${exampleToken}`,
        authorization: `Bearer ${exampleAntiCSRFToken}`,
      };
      try {
        getTokenFromAuthorizationCookieWithCSRFProtection({ headers });
      } catch (error) {
        expect(error).toBeInstanceOf(PotentialCSRFAttackError);
        expect(error.message).toEqual(
          `Potential cross-site-request-forgery attack detected!!! source origin can not be detected from request. no origin or referrer.`,
        );
      }
    });
  });
  describe('Token Based Mitigation', () => {
    it('should throw a CSRFAttemptError if no anti-csrf-token was passed in with the request', () => {
      const headers = {
        cookie: `authorization=${exampleToken}`,
        origin: 'https://www.whodis.io',
      };
      try {
        getTokenFromAuthorizationCookieWithCSRFProtection({ headers });
      } catch (error) {
        expect(error).toBeInstanceOf(PotentialCSRFAttackError);
        expect(error.message).toContain(`Potential cross-site-request-forgery attack detected!!!`);
        expect(error.message).toContain(`no anti-csrf-token was passed in the request!`);
      }
    });
    it('should throw a XSSVulnerabilityError if the anti-csrf-token does not have a redacted signature', () => {
      const headers = {
        cookie: `authorization=${exampleToken}`,
        authorization: `Bearer ${exampleToken}`, // e.g. the user's js had the real token and submitted it
        origin: 'https://www.whodis.io',
      };
      try {
        getTokenFromAuthorizationCookieWithCSRFProtection({ headers });
      } catch (error) {
        expect(error).toBeInstanceOf(PotentialXSSVulnerabilityError); // XSS Vulnerability, since user's js should _never_ have the real token. that's the point of putting it into the cookie, to prevent the token from getting stolen with XSS
        expect(error.message).toContain(`Potential cross-site-scripting vulnerability detected!`);
        expect(error.message).toContain(`anti-csrf-token found without redacted signature!`);
      }
    });
    it('should throw a CSRFAttemptError if the claims of the anti-csrf-token do not match the auth token, since not synchronized', () => {
      const differentExampleToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJmNWY3N2JjMC1iZTkwLTRmNGEtYmUyNS03MThjYjUwZjBmMGEiLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiaHR0cHM6Ly9hcGkud2hvZGlzLmlvIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.rlUwTF0FKufTFVS8YN-dAJY7e9DwwDs4DVrkflbXmU4`;
      const headers = {
        cookie: `authorization=${differentExampleToken}`,
        authorization: `Bearer ${exampleAntiCSRFToken}`,
        origin: 'https://www.whodis.io',
      };
      try {
        getTokenFromAuthorizationCookieWithCSRFProtection({ headers });
      } catch (error) {
        expect(error).toBeInstanceOf(PotentialCSRFAttackError);
        expect(error.message).toContain(`Potential cross-site-request-forgery attack detected!!!`);
        expect(error.message).toContain(`anti-csrf-token is not synchronized with token`);
      }
    });
    it('should throw a CSRFAttemptError if the header claims of the anti-csrf-token do not match the auth token, since not synchronized', () => {
      const differentExampleToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Mn0.eyJqdGkiOiJmNWY3N2JjMC1iZTkwLTRmNGEtYmUyNS0wMThjYjUwZjBmMGEiLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiaHR0cHM6Ly9hcGkud2hvZGlzLmlvIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.7FZ7yh4BJiPeVtvMsdXwjAAJatfXnXFoVEnhtqqJvJc`;
      const antiCSRFToken = redactSignature({ token: differentExampleToken });
      const headers = {
        cookie: `authorization=${differentExampleToken}`,
        authorization: `Bearer ${antiCSRFToken}`,
        origin: 'https://www.whodis.io',
      };
      try {
        getTokenFromAuthorizationCookieWithCSRFProtection({ headers });
      } catch (error) {
        expect(error).toBeInstanceOf(PotentialCSRFAttackError);
        expect(error.message).toContain(`Potential cross-site-request-forgery attack detected!!!`);
        expect(error.message).toContain(`anti-csrf-token is not synchronized with token`);
      }
    });
    it('should throw a CSRFVulnerabilityError if the token does not have a jti', () => {
      const exampleTokenWithoutJTI = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiaHR0cHM6Ly9hcGkud2hvZGlzLmlvIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.icPQtOxR2yKAukuhuS0TzI3lUA_KIRWiVfVURC2grqE`;
      const antiCSRFToken = redactSignature({ token: exampleTokenWithoutJTI });
      const headers = {
        cookie: `authorization=${exampleTokenWithoutJTI}`,
        authorization: `Bearer ${antiCSRFToken}`,
        origin: 'https://www.whodis.io',
      };
      try {
        getTokenFromAuthorizationCookieWithCSRFProtection({ headers });
      } catch (error) {
        expect(error).toBeInstanceOf(PotentialCSRFVulnerabilityError);
        expect(error.message).toContain(`Potential cross-site-request-forgery vulnerability detected!`);
        expect(error.message).toContain(`token.jki is not a uuid - can not guarantee randomness of token`);
      }
    });
    it('should throw a CSRFVulnerabilityError if the token does not have a uuid for the jti', () => {
      const exampleTokenWithoutJTI = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOjgyMSwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6Imh0dHBzOi8vYXBpLndob2Rpcy5pbyIsIm5hbWUiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMn0.zBfw2p-iChxf6FezT0HFvk_pNPbZ7Y3gIwce1qfeP4A`;
      const antiCSRFToken = redactSignature({ token: exampleTokenWithoutJTI });
      const headers = {
        cookie: `authorization=${exampleTokenWithoutJTI}`,
        authorization: `Bearer ${antiCSRFToken}`,
        origin: 'https://www.whodis.io',
      };
      try {
        getTokenFromAuthorizationCookieWithCSRFProtection({ headers });
      } catch (error) {
        expect(error).toBeInstanceOf(PotentialCSRFVulnerabilityError);
        expect(error.message).toContain(`Potential cross-site-request-forgery vulnerability detected!`);
        expect(error.message).toContain(`token.jki is not a uuid - can not guarantee randomness of token`);
      }
    });
  });
});
