import path from 'path';
import {assert} from '@artlab/bsert';
import {x509} from '../../../encoding/x509';
import {pem} from '../../../encoding/pem';
import fs from 'fs';

const CERTS_FILE = path.resolve(__dirname, '..', '..', 'data', 'certs.pem');
const CERT1_FILE = path.resolve(
  __dirname,
  '..',
  '..',
  'data',
  'x509-cert1.hex',
);
const CERT2_FILE = path.resolve(
  __dirname,
  '..',
  '..',
  'data',
  'x509-cert2.hex',
);

const certsPem = fs.readFileSync(CERTS_FILE, 'utf8');
const cert1Data = Buffer.from(
  fs
    .readFileSync(CERT1_FILE, 'utf8')
    .toString()
    .replace(/[\n\r ]/g, ''),
  'hex',
);
const cert2Data = Buffer.from(
  fs
    .readFileSync(CERT2_FILE, 'utf8')
    .toString()
    .replace(/[\n\r ]/g, ''),
  'hex',
);

function clear(crt: x509.Certificate) {
  crt.raw = null;
  crt.tbsCertificate.raw = null;
  crt.tbsCertificate.subjectPublicKeyInfo.raw = null;
}

describe('x509', function () {
  describe('from pem', function () {
    let i = 0;
    for (const block of pem.decode(certsPem)) {
      it(`should deserialize and re-serialize certificate (${i++})`, () => {
        const crt1 = x509.Certificate.decode<x509.Certificate>(block.data);
        const raw1 = crt1.encode();
        const crt2 = x509.Certificate.decode<x509.Certificate>(raw1);
        const raw2 = crt2.encode();

        clear(crt1);
        clear(crt2);

        assert.deepStrictEqual(crt1, crt2);
        assert.bufferEqual(raw1, raw2);
      });
    }
  });

  describe('from hex', function () {
    let i = 0;
    for (const data of [cert1Data, cert2Data]) {
      it(`should encode and decode certificate ${i++}`, function () {
        const cert1 = x509.Certificate.decode<x509.Certificate>(data);
        const raw1 = cert1.encode();
        const cert2 = x509.Certificate.decode<x509.Certificate>(raw1);
        const raw2 = cert2.encode();

        clear(cert1);
        clear(cert2);

        assert.deepStrictEqual(cert1, cert2);
        assert.bufferEqual(raw1, raw2);
        assert.deepEqual(raw1, data);
      });
    }
  });
});
