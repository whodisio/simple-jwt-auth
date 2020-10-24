import { getTokenFromHeaders } from './getTokenFromHeaders';
import { redactSignature } from '../redactSignature';
import { getUnauthedClaims } from '../getUnauthedClaims';
import { PotentialCSRFAttackError } from './PotentialCSRFAttackError';

const exampleToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJmNWY3N2JjMC1iZTkwLTRmNGEtYmUyNS0wMThjYjUwZjBmMGEiLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiaHR0cHM6Ly9hcGkud2hvZGlzLmlvIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.M_-_WjXeURe5M7JplujTq2Bl1V-MTm-Gxy9-DN4Qr8Q`;

describe('getTokenFromHeaders', () => {
  it('should get the token from authorization headers', () => {
    const headers = { authorization: `Bearer ${exampleToken}` };
    const { token } = getTokenFromHeaders({ headers });
    expect(token).toEqual(exampleToken);
  });
  it('should get the token from cookie headers', () => {
    const headers = {
      cookie: `authorization=${exampleToken}`,
      authorization: `Bearer ${redactSignature({ token: exampleToken })}`, // required for CSRF protection
      origin: getUnauthedClaims({ token: exampleToken }).aud, // required for CSRF protection
    };
    const { token } = getTokenFromHeaders({ headers });
    expect(token).toEqual(exampleToken);
  });
  it('should throw PotentialCSRFAttack errors if one of the CSRF conditions is not met', () => {
    const headers = {
      cookie: `authorization=${exampleToken}`,
      origin: 'https://evil-attacker.com', // attacker sends a request, without an anti-csrf-token too
    };
    try {
      getTokenFromHeaders({ headers });
      throw new Error('should not reach here');
    } catch (error) {
      expect(error).toBeInstanceOf(PotentialCSRFAttackError);
    }
  });
});
