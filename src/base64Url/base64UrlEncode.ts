import { castBase64ToBase64Url } from './castBase64ToBase64Url';

/**
 * converts base64 into base64Url
 */
export const base64UrlEncode = (str: string) =>
  castBase64ToBase64Url(Buffer.from(str, 'utf-8').toString('base64'));
