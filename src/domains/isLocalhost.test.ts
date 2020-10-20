import { isLocalhost } from './isLocalhost';

describe('isLocalhost', () => {
  it('should consider a simple localhost uri as from localhost', () => {
    const localhost = isLocalhost('https://localhost/hello/world');
    expect(localhost).toEqual(true);
  });
  it('should consider a localhost with port in uri as from localhost', () => {
    const localhost = isLocalhost('https://localhost:3000/hello/world');
    expect(localhost).toEqual(true);
  });
  it('should consider a localhost uri as from localhost even in http mode', () => {
    const localhost = isLocalhost('http://localhost:3000/hello/world');
    expect(localhost).toEqual(true);
  });
  it('it should not consider a normal domain as localhost', () => {
    const localhost = isLocalhost('http://whodis.io/docs');
    expect(localhost).toEqual(false);
  });
  it('it should not consider a domain that has localhost as subdomain to be localhost', () => {
    const localhost = isLocalhost('http://localhost.attacker.co/free-candy');
    expect(localhost).toEqual(false);
  });
});
