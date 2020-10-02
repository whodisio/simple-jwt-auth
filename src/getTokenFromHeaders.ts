import { isJSONWebToken } from './isJSONWebToken';
import { SimpleJwtAuthError } from './SimpleJwtAuthError';

export const getTokenFromHeaders = ({ headers }: { headers: Record<string, any> }): string | null => {
  // grab the authorization header field
  if (!headers) throw new SimpleJwtAuthError('headers must be defined to getTokenFromHeader');
  const authorization = headers.authorization ?? headers.Authorization ?? null; // headers are case-insensitive, by spec: https://stackoverflow.com/a/5259004/3068233
  if (!authorization) return null;
  const potentiallyAToken = authorization.replace(/^Bearer /i, '');
  if (!isJSONWebToken(potentiallyAToken)) return null; // check that it looks like a token, since other strings can be passed here
  return potentiallyAToken;
};
