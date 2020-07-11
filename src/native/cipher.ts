import {AeadOptions, CipherExports} from '../types/cipher';
import {assert} from '../internal/assert';
import {decrypt, encrypt} from '../internal/cipher';

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

  cipher.encrypt = (
    name: string,
    key: Buffer,
    iv: Buffer,
    data: Buffer,
    tagLen?: number,
  ) => encrypt(cipher.Cipher, name, key, iv, data, tagLen);

  cipher.decrypt = (
    name: string,
    key: Buffer,
    iv: Buffer,
    data: Buffer,
    tagOrLen?: number | Buffer,
  ) => decrypt(cipher.Decipher, name, key, iv, data, tagOrLen);
}
