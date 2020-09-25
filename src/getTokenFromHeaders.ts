import { SimpleJwtAuthError } from './SimpleJwtAuthError';

export const getTokenFromHeaders = ({ headers }: { headers: Record<string, any> }): string | null => {
  if (!headers) throw new SimpleJwtAuthError('headers must be defined to getTokenFromHeader');
  if (!headers.Authorization) return null;
  const potentiallyAToken = headers.Authorization.replace(/^Bearer /i, '');
  if (potentiallyAToken.split('.').length !== 3) return null; // check that it looks like a token, since other strings can be passed here
  return potentiallyAToken;
};
