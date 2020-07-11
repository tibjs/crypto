import {assert} from '../internal/assert';
import {AeadOptions, CipherExports} from '../types';
import {decrypt, encrypt, safeEqual} from '../internal/cipher';

const cipher: CipherExports = require('bcrypto/lib/js/cipher');

export = cipher;

/****************************************
 * Hacking for support AeadOptions
 ****************************************/
const {Mode, GCM, CCM} = require('bcrypto/lib/js/ciphers/modes');
const {Cipher, Decipher} = cipher;

if (!Mode.prototype.setAead) {
  Mode.prototype.setAead = function setAead() {
    throw new Error('Not implemented.');
  };

  // GCM patch
  GCM.prototype.setAead = function (options?: AeadOptions) {
    const tagLen = options?.tagLen ?? 16;
    assert(tagLen === 4 || tagLen === 8 || (tagLen >= 12 && tagLen <= 16));
    this.tagLen = tagLen;
  };

  GCM.prototype._final = function () {
    const mac = this.hash.final();

    for (let i = 0; i < 16; i++) mac[i] ^= this.mask[i];

    if (this.encrypt) {
      this.mac = mac.slice(0, this.tagLen);
      return Buffer.alloc(0);
    }

    if (!this.tag) throw new Error('No tag provided.');

    if (!safeEqual(mac, this.tag, this.tag.length))
      throw new Error('Invalid tag.');

    return Buffer.alloc(0);
  };

  // CCM patch
  CCM.prototype.setAead = function (options?: AeadOptions) {
    if (!options) {
      return this;
    }
    assert(options.msgLen, 'msgLen is required');
    assert(options.tagLen, 'tagLen is required');
    return this._setCCM(options.msgLen, options.tagLen, options.aad);
  };

  // Cipher and Decipher patch
  function cipherSetAead(this: any, options?: AeadOptions) {
    this.ctx.setAead(options);
    return this;
  }

  [Cipher, Decipher].forEach(cls => (cls.prototype.setAead = cipherSetAead));

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
