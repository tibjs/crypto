import {expect} from '@artlab/testlab';
import {cipher} from '../../cipher';
import js_cipher from '../../js/cipher';
import native_cipher from '../../native/cipher';
import vectors = require('../data/cipher');
import {CipherExports} from '../../types/cipher';

describe('cipher', () => {
  describe('patching', function() {
    it('should exports native cipher default', function() {
      expect(native_cipher).equal(cipher);
    });

    it('should patched setAead', function() {
      expect(js_cipher.Cipher.prototype.setAead).type('function');
      expect(native_cipher.Cipher.prototype.setAead).type('function');
    });
  });

  describe('js/cipher', function() {
    for (const [alg, key, iv, pt, ct, tag, aad] of vectors) {
      itCipherAndDecipher(js_cipher, alg, key, iv, pt, ct, tag, aad);
    }
  });

  describe('native/cipher', function() {
    const vectors_ = vectors.filter(v => !v[0].endsWith('GCM'));
    for (const [alg, key, iv, pt, ct, tag, aad] of vectors_) {
      itCipherAndDecipher(native_cipher, alg, key, iv, pt, ct, tag, aad);
    }
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
  aad: Buffer
) {
  const text = key.slice(0, 16);
  it(`should perform ${alg} ${text}`, function() {
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
