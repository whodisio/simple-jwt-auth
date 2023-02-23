/**
 * given base64Url string, decodes it into a base64
 */
export const castBase64UrlToBase64 = (base64Url: string) =>
  base64Url.replace(/-/g, '+').replace(/_/g, '/');
