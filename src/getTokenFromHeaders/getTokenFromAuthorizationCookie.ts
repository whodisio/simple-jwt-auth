/* eslint-disable @typescript-eslint/naming-convention */
import { isJSONWebToken } from '../isJSONWebToken';

export const getTokenFromAuthorizationCookie = ({
  headers,
}: {
  headers: Record<string, any>;
}): string | null => {
  // grab the authorization cookie field
  const cookies = headers.cookie ?? headers.Cookie ?? null; // headers are case-insensitive, by spec: https://stackoverflow.com/a/5259004/3068233
  if (!cookies) return null;
  const [_, authorization] =
    new RegExp(/ (authorization=[a-zA-Z0-9\-_.]+);/i).exec(` ${cookies};`) ??
    [];
  if (!authorization) return null; // auth cookie not found
  const potentiallyAToken = authorization.replace(/^authorization=/, ''); // case sensitive: https://stackoverflow.com/a/11312272/3068233
  if (!isJSONWebToken(potentiallyAToken)) return null; // check that it looks like a token, since other strings can be passed here
  return potentiallyAToken;
};
