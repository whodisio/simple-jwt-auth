import { SimpleJwtAuthError } from '../SimpleJwtAuthError';
import { getTokenFromAuthorizationCookie } from './getTokenFromAuthorizationCookie';
import { getTokenFromAuthorizationHeader } from './getTokenFromAuthorizationHeader';

export enum TokenFromHeadersSource {
  AUTHORIZATION_COOKIE = 'AUTHORIZATION_COOKIE',
  AUTHORIZATION_HEADER = 'AUTHORIZATION_HEADER',
}
export const getTokenFromHeaders = ({
  headers,
}: {
  headers: Record<string, any>;
}): { token: string | null; source: TokenFromHeadersSource | null } => {
  // sanity check that headers are actually defined; otherwise, developer probably is not using this function correctly - so fail fast
  if (!headers) throw new SimpleJwtAuthError('headers must be defined to getTokenFromHeaders');

  // try to grab the token from auth cookie (w/ CSRF protection)
  const tokenFromAuthCookie = getTokenFromAuthorizationCookie({ headers });
  if (tokenFromAuthCookie) return { token: tokenFromAuthCookie, source: TokenFromHeadersSource.AUTHORIZATION_COOKIE };

  // try to grab the token from auth header
  const tokenFromAuthHeader = getTokenFromAuthorizationHeader({ headers });
  if (tokenFromAuthHeader) return { token: tokenFromAuthHeader, source: TokenFromHeadersSource.AUTHORIZATION_HEADER };

  // if neither worked, return null
  return { token: null, source: null };
};
