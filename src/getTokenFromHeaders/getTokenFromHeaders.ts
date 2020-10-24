import { SimpleJwtAuthError } from '../SimpleJwtAuthError';
import { getTokenFromAuthorizationCookieWithCSRFProtection } from './getTokenFromAuthorizationCookieWithCSRFProtection';
import { getTokenFromAuthorizationHeader } from './getTokenFromAuthorizationHeader';

export const getTokenFromHeaders = ({ headers }: { headers: Record<string, any> }): string | null => {
  // sanity check that headers are actually defined; otherwise, developer probably is not using this function correctly - so fail fast
  if (!headers) throw new SimpleJwtAuthError('headers must be defined to getTokenFromHeaders');

  // try to grab the token from auth cookie (w/ CSRF protection)
  const tokenFromAuthCookie = getTokenFromAuthorizationCookieWithCSRFProtection({ headers });
  if (tokenFromAuthCookie) return tokenFromAuthCookie;

  // try to grab the token from auth header
  const tokenFromAuthHeader = getTokenFromAuthorizationHeader({ headers });
  if (tokenFromAuthHeader) return tokenFromAuthHeader;

  // if neither worked, return null
  return null;
};
