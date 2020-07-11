import path from 'path';
import fs from 'fs';
import {assert} from '@artlab/bsert';
import {pem} from '../../../encoding/pem';
import {pkcs10} from '../../../encoding/pkcs10';

function clear(csr: pkcs10.CertificationRequest) {
  csr.raw = null;
  csr.certificationRequestInfo.raw = null;
  csr.certificationRequestInfo.subjectPublicKeyInfo.raw = null;
}

const CSRS_FILE = path.resolve(__dirname, '..', '..', 'data', 'csrs.pem');

const csrsPem = fs.readFileSync(CSRS_FILE, 'utf8');

describe('pkcs10', () => {
  describe('from pem', function () {
    let i = 0;
    for (const block of pem.decode(csrsPem)) {
      it(`should deserialize and re-serialize certification request (${i++})`, () => {
        const csr1 = <pkcs10.CertificationRequest>(
          pkcs10.CertificationRequest.decode(block.data)
        );
        const raw1 = csr1.encode();
        const csr2 = <pkcs10.CertificationRequest>(
          pkcs10.CertificationRequest.decode(raw1)
        );
        const raw2 = csr2.encode();

        clear(csr1);
        clear(csr2);

        assert.deepStrictEqual(csr1, csr2);
        assert.bufferEqual(raw1, raw2);
      });
    }
  });
});
