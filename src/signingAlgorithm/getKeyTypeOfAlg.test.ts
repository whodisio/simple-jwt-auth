import { given, then } from 'test-fns';

import { getKeyTypeOfAlg } from './getKeyTypeOfAlg';
import type { AsymmetricSigningAlgorithm } from './isAsymmetricSigningAlgorithm';

/**
 * .what = every asymmetric alg this package signs with, and the key type each needs
 * .why = the sign-side guard trusts this map; each alg is pinned, not only the two the guard tests drive
 */
const TEST_CASES: { alg: AsymmetricSigningAlgorithm; keyType: 'rsa' | 'ec' }[] =
  [
    { alg: 'RS256', keyType: 'rsa' },
    { alg: 'RS384', keyType: 'rsa' },
    { alg: 'RS512', keyType: 'rsa' },
    { alg: 'ES256', keyType: 'ec' },
    { alg: 'ES384', keyType: 'ec' },
  ];

describe('getKeyTypeOfAlg', () => {
  TEST_CASES.map((thisCase) =>
    given(`alg ${thisCase.alg}`, () => {
      then(`it needs an '${thisCase.keyType}' key`, () => {
        expect(getKeyTypeOfAlg({ alg: thisCase.alg })).toEqual(
          thisCase.keyType,
        );
      });
    }),
  );
});
