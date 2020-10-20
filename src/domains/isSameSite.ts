import { fromUrl, parseDomain, ParseResultType } from 'parse-domain';

/**
 * check whether two URI's are from the same "site" (i.e., domain / hostname)
 *
 * used in CORS and anti-CSRF use cases relevant for authenticating JWTs, common in browser authentication settings
 *
 * this closely reflects logic that is conducted when determining whether two domains are the "same site" in the `SameSite` mechanism of HTTP cookies
 *  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
 *
 * NOTE: this function is designed to lean false negative - and be conservative with what it says the same sites are
 */
export const isSameSite = (uriA: string, uriB: string) => {
  // extract the domains from the two uris (https://nodejs.org/api/url.html#url_the_whatwg_url_api)
  const domainsOfA = parseDomain(fromUrl(uriA));
  if (domainsOfA.type !== ParseResultType.Listed) return false; // if the domain is not listed, we can't get enough info about it to confirm
  const domainsOfB = parseDomain(fromUrl(uriB));
  if (domainsOfB.type !== ParseResultType.Listed) return false; // if the domain is not listed, we can't get enough info about it to confirm

  // check that the two domains, considering the public suffixes and excluding subdomains, are the same
  const rootHostnameOfA = [domainsOfA.domain, ...domainsOfA.topLevelDomains].join('.');
  const rootHostnameOfB = [domainsOfB.domain, ...domainsOfB.topLevelDomains].join('.');
  return rootHostnameOfA === rootHostnameOfB;
};
