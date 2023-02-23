import { v4 as uuid } from 'uuid';

import { isUuid } from './isUuid';

describe('isUuid', () => {
  it('should return true for real uuid', () => {
    expect(isUuid(uuid())).toEqual(true);
  });
  it('should return false for non uuid', () => {
    expect(isUuid('821')).toEqual(false);
  });
  it('should return false for nil uuid', () => {
    expect(isUuid('0000000-0000-0000-0000-000000000000')).toEqual(false);
  });
});
