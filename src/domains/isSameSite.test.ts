import { isSameSite } from './isSameSite';

describe('isSameSite', () => {
  it('should find that the same uri is the same site', () => {
    const sameSite = isSameSite('https://api.WHODIS.io', 'https://api.whodis.io');
    expect(sameSite).toEqual(true);
  });
  it('should find that the same uri is the same site, regardless of subdomain', () => {
    const sameSite = isSameSite('https://api.whodis.io', 'https://www.whodis.io');
    expect(sameSite).toEqual(true);
  });
  it('should find that the two uri with different paths from the same host is the same site', () => {
    const sameSite = isSameSite('https://api.whodis.io', 'https://www.whodis.io/hello/there');
    expect(sameSite).toEqual(true);
  });
  it('should find that two difference uris are not the same site', () => {
    const sameSite = isSameSite('https://api.whodis.io', 'https://api.ahbode.com');
    expect(sameSite).toEqual(false);
  });
  it('should find that two uris are not the same site if their "domain" is a wellknown public domain (e.g., `github.io` which hosts user pages)', () => {
    const sameSite = isSameSite('https://parse-domain.github.io', 'https://simple-jwt-auth.github.io');
    expect(sameSite).toEqual(false);
  });
  it('should find that two uris are not the same site if their "domain" is a wellknown public domain (e.g., `cloudfront.net` which hosts/proxies sites for folks)', () => {
    const sameSite = isSameSite('https://zt5q821v7ck9b.cloudfront.net', 'https://dt5t8217r0k9c.cloudfront.net');
    expect(sameSite).toEqual(false);
  });
  it('should find that two uris are not the same site, even if one of them includes the other', () => {
    const sameSite = isSameSite('example.org.attacker.com', 'example.org');
    expect(sameSite).toEqual(false);
  });
});
