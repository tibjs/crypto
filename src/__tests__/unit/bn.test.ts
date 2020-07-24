import {expect} from '@tib/testlab';
import {BN} from '../../bn';

describe('BN', function () {
  it('should import correctly', function () {
    expect(BN).ok();
    expect(BN.name).equal('BN');
  });
});
