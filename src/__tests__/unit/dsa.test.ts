import {dsa} from '../../dsa';
import {expect} from '@tib/testlab';

describe('dsa', function () {
  it('should import correctly', function () {
    expect(dsa).ok();
    expect(dsa.derive).type('function');
  });
});
