import { castBase64UrlToBase64 } from './castBase64UrlToBase64';

export const base64UrlDecode = (base64Url: string) =>
  Buffer.from(castBase64UrlToBase64(base64Url), 'base64').toString('utf-8');
