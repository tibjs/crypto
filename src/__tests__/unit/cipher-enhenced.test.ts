import {expect} from '@tib/testlab';
import {cipher} from '../../cipher';
import vectors = require('../data/cipher');
import {CipherExports} from '../../types';

describe('cipher', () => {
  describe('patching', function () {
    it('should patched setAead', function () {
      expect(cipher.Cipher.prototype.setAead).type('function');
    });
  });

  describe('aead', function () {
    const vectors_ = cipher.native
      ? vectors.filter(v => v[0].endsWith('CCM'))
      : vectors;

    describe('cipher/decipher', function () {
      for (const [alg, key, iv, pt, ct, tag, aad] of vectors_) {
        itCipherAndDecipher(cipher, alg, key, iv, pt, ct, tag, aad);
      }
    });

    describe('encrypt/decrypt', function () {
      for (const [alg, key, iv, pt, ct, tag] of vectors_) {
        itEncryptAndDecrypt(cipher, alg, key, iv, pt, ct, tag);
      }
    });
  });
});

function itCipherAndDecipher(
  mod: CipherExports,
  alg: string,
  key: Buffer,
  iv: Buffer,
  pt: Buffer,
  ct: Buffer,
  tag: Buffer,
  aad: Buffer,
) {
  const text = key.slice(0, 16);
  it(`should perform Cipher/Decipher with ${alg} ${text}`, function () {
    const c = new mod.Cipher(alg);
    const d = new mod.Decipher(alg);
    c.init(key, iv);
    c.setAead({msgLen: pt.length, tagLen: tag.length, aad});

    d.init(key, iv);
    d.setAead({msgLen: pt.length, tagLen: tag.length, aad});
    d.setAuthTag(tag);

    const ct0 = c.update(pt);
    c.final();

    const mac = c.getAuthTag();

    expect(mac).deepEqual(tag);
    expect(ct0).deepEqual(ct);

    const pt0 = d.update(ct);

    d.final();
    expect(pt0).deepEqual(pt);
  });
}

function itEncryptAndDecrypt(
  mod: CipherExports,
  alg: string,
  key: Buffer,
  iv: Buffer,
  pt: Buffer,
  ct: Buffer,
  tag: Buffer,
) {
  const text = key.slice(0, 16);
  it(`should perform encrypt/decrypt with ${alg} ${text}`, function () {
    const ct0 = mod.encrypt(alg, key, iv, pt, tag.length);
    expect(ct0).deepEqual(Buffer.concat([ct, tag]));
    const pt0 = mod.decrypt(alg, key, iv, ct, tag);
    expect(pt0).deepEqual(pt);
  });
}
