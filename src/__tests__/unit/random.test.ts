import {expect} from '@tib/testlab';
import {random} from '../../random';

describe('Random', function () {
  it('should import correctly', () => {
    expect(random).ok();
    expect(random.randomBytes).type('function');
  });
});
