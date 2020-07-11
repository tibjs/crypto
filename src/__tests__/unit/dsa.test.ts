import {dsa} from '../../dsa';
import {expect} from '@artlab/testlab';

describe('dsa', function () {
  it('should import correctly', function () {
    expect(dsa).ok();
    expect(dsa.derive).type('function');
  });
});
