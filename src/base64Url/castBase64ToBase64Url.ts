/**
 * given base64 string, encodes it into a base64Url
 */
export const castBase64ToBase64Url = (str: string) =>
  str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
