import path from 'path';
import fs from 'fs';
import {assert} from '@tib/bsert';
import {rfc3279} from '../../../encoding';

const DSA_PARAMS = path.resolve(
  __dirname,
  '..',
  '..',
  'data',
  'dsa-parameters.pem',
);

const dsaParamsPem = fs.readFileSync(DSA_PARAMS, 'utf8');
const dsaParamsJson = require('../../data/dsa-parameters.json');

describe('RFC3279', function () {
  it('should deserialize DSA parameters', () => {
    const key = rfc3279.DSAParams.fromPEM<rfc3279.DSAParams>(dsaParamsPem);
    const json = dsaParamsJson;

    assert.strictEqual(key.p.value.toString('hex'), json.p);
    assert.strictEqual(key.q.value.toString('hex'), json.q);
    assert.strictEqual(key.g.value.toString('hex'), json.g);

    assert.strictEqual(key.toPEM(), dsaParamsPem);
  });
});
