import { isSameSite } from '../domains/isSameSite';
import { getUnauthedClaims } from '../getUnauthedClaims';
import { getUnauthedHeaderClaims } from '../getUnauthedHeaderClaims';
import { getTokenFromAuthorizationCookie } from './getTokenFromAuthorizationCookie';
import { getTokenFromAuthorizationHeader } from './getTokenFromAuthorizationHeader';
import { isUuid } from './isUuid';
import { PotentialCSRFAttackError } from './PotentialCSRFAttackError';
import { PotentialCSRFVulnerabilityError } from './PotentialCSRFVulnerabilityError';
import { PotentialXSSVulnerabilityError } from './PotentialXSSVulnerabilityError';

/**
 * simple utility used below, makes the code a little easier to read
 */
const serialize = (obj: object) => JSON.stringify(obj);

/**
 * Cross Site Request Forgery (CSRF) may occur whenever a server receiving a cookie does not check where that cookie is sent from.
 *  - in otherwords, CSRF is a risk that arises when only two of the three parts of principled auth are checked (the audience - your server, the payload - the token, but not the issuer of the request (in this case, an attacker))
 *
 * This vulnerability exists due to the default behavior of a browser to send all cookies on a user's browser that match a server, regardless of which site they are on when making the request.
 *
 * Recent standards have lead to the rise of the `SameSite` cookie policy, but this alone is not sufficient to protect users from CSRF.
 *
 * Following the recommendations of [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), this function implements a strong two layer defence against CSRF:
 *  1. [Verifying Origin with Standard Headers](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#verifying-origin-with-standard-headers)
 *    - "Reliability on these headers comes from the fact that they cannot be altered programmatically (using JavaScript with an XSS vulnerability) as they fall under forbidden headers list, meaning that only the browser can set them"
 *  2. [Token Based Mitigation](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#token-based-mitigation)
 *    - "CSRF tokens prevent CSRF because without token, attacker cannot create a valid requests to the backend server."
 *
 * The implementation of Verifying Origin with Standard Headers that this library supports depends the `audience` claim of the JWT.
 *   - specifically, it assumes that the "target origin" is defined as the audience of the token, `jwt.aud`.
 *   - that means that to check `isSameSite("source origin", "target origin")`, we will check `isSameSite(req.origin ?? req.referrer, jwt.aud)`
 *     - details on implementation of `isSameSite` can be found in the JSDOC of that method, exported by this library.
 *
 * The implementation of Token Based Mitigation that this library supports is a form of Distributed, Per-Session, Synchronizer token.
 *   - specifically, this library expects and enforces that
 *     - a unauthenticatable, signature redacted token is passed in the typical `authorization` header
 *       - i.e., a jwt with signature = `___REDACTED__`
 *       - note: signature being redacted is critical, as this confirms that the browser does not have access to an authenticatable token, which would leave the user susceptible to having their token stolen through XSS
 *     - an authenticatable token to be passed in the `authorization` cookie
 *     - that the body of the unauthenticatable token from the auth-header is equivalent to the body of the authenticatable token of the auth-cookie
 *     - that the tokens contain a unique, random JTI (format: a uuid)
 *  - by requiring the website that the user logs into to locally persist a `unauthenticatable` version of the token, we:
 *    - give that website a unique, random anti-CSRF token which can not be accessed CrossSite nor be deduced from JS.
 *
 * Warning: CSRF is only relevant to security when the auth cookie is protected with `Secure` and `HTTPOnly` settings. Otherwise, MITM and XSS will be able to steal the cookie and CSRF will be the least of our concerns.
 */
export const getTokenFromAuthorizationCookieWithCSRFProtection = ({ headers }: { headers: Record<string, any> }): string | null => {
  // attempt to grab the jwt from the auth cookie
  const token = getTokenFromAuthorizationCookie({ headers });
  if (!token) return null; // if no token in cookie, do nothing

  // check for CSRF, checking that the "source origin" is samesite as "target origin"
  const sourceOrigin: string = headers.origin ?? headers.Origin ?? headers.referrer ?? headers.Referrer;
  if (!sourceOrigin) throw new PotentialCSRFAttackError({ reason: 'source origin can not be detected from request. no origin or referrer.' });
  const targetOrigin = getUnauthedClaims({ token }).aud;
  if (!isSameSite(sourceOrigin, targetOrigin))
    throw new PotentialCSRFAttackError({
      reason: `source origin is not same site as target origin! (target='${targetOrigin}', source='${sourceOrigin}')`,
    });

  // now check for CSRF, expecting a synchronized anti-csrf token in the auth header
  const antiCsrfToken = getTokenFromAuthorizationHeader({ headers });
  if (!antiCsrfToken) throw new PotentialCSRFAttackError({ reason: 'no anti-csrf-token was passed in the request!' }); // check that anti-csrf-token was defined
  const antiCsrfTokenSignature = antiCsrfToken.split('.')[2];
  if (antiCsrfTokenSignature !== '__REDACTED__')
    throw new PotentialXSSVulnerabilityError({ reason: 'anti-csrf-token found without redacted signature!' }); // check that anti-csrf-token has redacted signature
  const antiCsrfTokenClaims = getUnauthedClaims({ token: antiCsrfToken });
  const antiCsrfTokenHeaderClaims = getUnauthedHeaderClaims({ token: antiCsrfToken });
  const tokenClaims = getUnauthedClaims({ token });
  const tokenHeaderClaims = getUnauthedHeaderClaims({ token });
  if (serialize(antiCsrfTokenClaims) !== serialize(tokenClaims))
    throw new PotentialCSRFAttackError({ reason: 'anti-csrf-token is not synchronized with token' }); // check that anti-csrf-token is correct
  if (serialize(antiCsrfTokenHeaderClaims) !== serialize(tokenHeaderClaims))
    throw new PotentialCSRFAttackError({ reason: 'anti-csrf-token is not synchronized with token' }); // check that anti-csrf-token is correct
  if (!tokenClaims.jti || !isUuid(tokenClaims.jti))
    throw new PotentialCSRFVulnerabilityError({ reason: 'token.jki is not a uuid - can not guarantee randomness of token' }); // check that token is random; this is probably overboard, but not a bad constraint to require conforming to

  // if both CSRF checks passed, then return the token. Its not a CSRF attempt
  return token;
};
