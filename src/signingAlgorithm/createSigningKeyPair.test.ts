import { createSigningKeyPair } from './createSigningKeyPair';

describe('createSigningKeyPair', () => {
  it('should be able to create rsa keypair', async () => {
    const keypair = await createSigningKeyPair('RS256');
    expect(keypair.publicKey.length).toEqual(451);
    expect(keypair.privateKey.length).toBeGreaterThan(1700);
  });
  it('should be able to create ecc keypair', async () => {
    const keypair = await createSigningKeyPair('ES256');
    expect(keypair.publicKey.length).toEqual(178);
    expect(keypair.privateKey.length).toEqual(241);
  });
});
