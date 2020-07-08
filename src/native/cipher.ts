import {AeadOptions, CipherExports} from '../types/cipher';
import {assert} from '@artlab/bsert';

const cipher: CipherExports = require('bcrypto/lib/native/cipher');

export = cipher;

const {Cipher, Decipher} = cipher;

if (!Cipher.prototype.setAead) {
  function setAead(this: any, options?: AeadOptions) {
    if (!options) {
      return this;
    }
    assert(options.msgLen, 'msgLen is required');
    assert(options.tagLen, 'tagLen is required');
    return this.setCCM(options.msgLen!, options.tagLen!, options.aad);
  }

  [Cipher, Decipher].forEach(cls => (cls.prototype.setAead = setAead));
}
