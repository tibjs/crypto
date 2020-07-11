import {CipherCtor, DecipherCtor} from '../types';
import {assert} from '../internal/assert';

export function safeEqual(x: any, y: any, len: number) {
  let z = 0;

  for (let i = 0; i < len; i++) z |= x[i] ^ y[i];

  return (z - 1) >>> 31;
}

export const modeNames: Record<string, any> = {
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

export function parseName(name: string) {
  if (name.length < 5) return [name, 'RAW'];

  const mode = name.substring(name.length - 3);

  if (name[name.length - 4] !== '-' || !modeNames[mode]) return [name, 'RAW'];

  const algo = name.substring(0, name.length - 4);

  return [algo, mode];
}

export function isAead(mode: string) {
  return ['GCM', 'CCM'].includes(mode.toUpperCase());
}

export function encrypt(
  Cipher: CipherCtor,
  name: string,
  key: Buffer,
  iv: Buffer,
  data: Buffer,
  tagLen?: number,
): Buffer {
  const [, mode] = parseName(name);
  const ctx = new Cipher(name);
  ctx.init(key, iv);
  if (tagLen != null) {
    ctx.setAead({tagLen, msgLen: data.length});
  }

  return Buffer.concat([
    ctx.update(data),
    ctx.final(),
    isAead(mode) ? ctx.getAuthTag() : Buffer.alloc(0),
  ]);
}

export function decrypt(
  Decipher: DecipherCtor,
  name: string,
  key: Buffer,
  iv: Buffer,
  data: Buffer,
  tagOrLen?: number | Buffer,
): Buffer {
  const [, mode] = parseName(name);
  const ctx = new Decipher(name);
  ctx.init(key, iv);

  if (isAead(mode) && tagOrLen != null) {
    assert(tagOrLen, 'tagOrLen is required in aead mode');
    let tag: Buffer = Buffer.alloc(0);
    if (typeof tagOrLen === 'number') {
      tag = data.slice(-tagOrLen);
      data = data.slice(0, -tagOrLen);
    } else if (Buffer.isBuffer(tagOrLen)) {
      tag = tagOrLen;
    } else {
      throw new Error('tagOrLen is invalid');
    }
    ctx.setAead({tagLen: tag.length, msgLen: data.length});
    ctx.setAuthTag(tag);
  }

  return Buffer.concat([ctx.update(data), ctx.final()]);
}
