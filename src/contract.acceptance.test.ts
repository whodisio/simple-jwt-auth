import { given, then, when } from 'test-fns';
import { v4 as uuid } from 'uuid';

import { mkdirSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('contract', () => {
  given('[case1] consumer imports from simple-jwt-auth', () => {
    const tempDir = join(tmpdir(), `simple-jwt-auth-test-${uuid()}`);
    const nodeModulesDir = join(tempDir, 'node_modules');
    const packageLink = join(nodeModulesDir, 'simple-jwt-auth');
    const gitRoot = join(__dirname, '..');

    beforeAll(() => {
      mkdirSync(nodeModulesDir, { recursive: true });
      symlinkSync(gitRoot, packageLink, 'dir');
    });

    afterAll(() => {
      rmSync(tempDir, { recursive: true, force: true });
    });

    when('[t0] require() is called', () => {
      then('it resolves to the package', () => {
        // require from the symlinked location to test package.json main field
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const pkg = require(packageLink);
        expect(pkg).toBeDefined();
        expect(typeof pkg.getAuthedClaims).toBe('function');
        expect(typeof pkg.getSignedClaims).toBe('function');
        expect(typeof pkg.isJSONWebToken).toBe('function');
        expect(typeof pkg.createSigningKeyPair).toBe('function');
      });
    });
  });
});
