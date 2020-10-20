import { isJSONWebToken } from '../isJSONWebToken';

export const getTokenFromAuthorizationHeader = ({ headers }: { headers: Record<string, any> }): string | null => {
  // grab the authorization header field
  const authorization = headers.authorization ?? headers.Authorization ?? null; // headers are case-insensitive, by spec: https://stackoverflow.com/a/5259004/3068233
  if (!authorization) return null;
  const potentiallyAToken = authorization.replace(/^Bearer /i, '');
  if (!isJSONWebToken(potentiallyAToken)) return null; // check that it looks like a token, since other strings can be passed here
  return potentiallyAToken;
};
