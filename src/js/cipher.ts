import {assert} from '@artlab/bsert';
import {AeadOptions, CipherExports} from '../types/cipher';

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

  cipher.encrypt = function encrypt(
    name: string,
    key: Buffer,
    iv: Buffer,
    data: Buffer,
    tagLen?: number,
  ): Buffer {
    const [, mode] = parseName(name);
    const ctx = new cipher.Cipher(name);
    ctx.init(key, iv);
    ctx.setAead({tagLen, msgLen: data.length});

    return Buffer.concat([
      ctx.update(data),
      ctx.final(),
      isAead(mode) ? ctx.getAuthTag() : Buffer.allocUnsafe(0),
    ]);
  };

  cipher.decrypt = function decrypt(
    name: string,
    key: Buffer,
    iv: Buffer,
    data: Buffer,
    tagOrLen?: number | Buffer,
  ): Buffer {
    const [, mode] = parseName(name);
    const ctx = new cipher.Decipher(name);
    ctx.init(key, iv);

    if (isAead(mode)) {
      tagOrLen = tagOrLen ?? 16;
      assert(tagOrLen, 'tagOrLen is required in aead mode');
      let tag: Buffer = Buffer.allocUnsafe(0);
      if (typeof tagOrLen === 'number') {
        tag = data.slice(-tagOrLen);
        data = data.slice(0, -tagOrLen);
      } else if (Buffer.isBuffer(tagOrLen)) {
        tag = tagOrLen;
      } else {
        throw new Error('tagOrLen is invalid');
      }
      ctx.setAuthTag(tag);
    }

    return Buffer.concat([ctx.update(data), ctx.final()]);
  };
}

function safeEqual(x: any, y: any, len: number) {
  let z = 0;

  for (let i = 0; i < len; i++) z |= x[i] ^ y[i];

  return (z - 1) >>> 31;
}

const modeNames: Record<string, any> = {
  __proto__: null,
  ECB: true,
  CBC: true,
  CTS: true,
  XTS: true,
  CTR: true,
  CFB: true,
  OFB: true,
  GCM: true,
  CCM: true,
  EAX: true,
};

function parseName(name: string) {
  if (name.length < 5) return [name, 'RAW'];

  const mode = name.substring(name.length - 3);

  if (name[name.length - 4] !== '-' || !modeNames[mode]) return [name, 'RAW'];

  const algo = name.substring(0, name.length - 4);

  return [algo, mode];
}

function isAead(mode: string) {
  return ['GCM', 'CCM'].includes(mode.toUpperCase());
}
