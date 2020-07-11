import {assert} from '../internal/assert';
import {Adsa, EDDSA, HashCtor} from '../types';

export function extend(asym: EDDSA): EDDSA {
  asym.algo = 'EDDSA';
  asym.adsa = (hash?: HashCtor): Adsa => new EDDSAAdsa(asym, hash);
  return asym;
}

class EDDSAAdsa implements Adsa {
  readonly id: string;

  constructor(public asym: EDDSA, protected hash?: HashCtor) {
    this.id = asym.id;
  }

  sign(
    msg: string | Buffer,
    key: any,
    ph: boolean | null,
    ctx: Buffer,
  ): Buffer {
    return this.signMessage(msg, key, ph, ctx);
  }

  signMessage(
    msg: string | Buffer,
    key: any,
    ph: boolean | null,
    ctx: Buffer,
  ): Buffer {
    assert(this.hash, 'hash is required');
    msg = Buffer.isBuffer(msg) ? msg : Buffer.from(msg, 'hex');
    return this.asym.sign(this.hash!.digest(msg), key, ph, ctx);
  }

  signDigest(
    digest: string | Buffer,
    key: Buffer,
    ph: boolean | null,
    ctx: Buffer,
  ): Buffer {
    digest = Buffer.isBuffer(digest) ? digest : Buffer.from(digest, 'hex');
    return this.asym.sign(digest, key, ph, ctx);
  }

  verify(
    msg: string | Buffer,
    sig: Buffer,
    key: any,
    ph: boolean | null,
    ctx: Buffer,
  ): boolean {
    return this.verifyMessage(msg, sig, key, ph, ctx);
  }

  verifyMessage(
    msg: string | Buffer,
    sig: Buffer,
    key: any,
    ph: boolean | null,
    ctx: Buffer,
  ): boolean {
    assert(this.hash, 'hash is required');
    msg = Buffer.isBuffer(msg) ? msg : Buffer.from(msg, 'hex');
    return this.asym.verify(this.hash!.digest(msg), sig, key, ph, ctx);
  }

  verifyDigest(
    digest: string | Buffer,
    sig: Buffer,
    key: Buffer,
    ph: boolean | null,
    ctx: Buffer,
  ): boolean {
    digest = Buffer.isBuffer(digest) ? digest : Buffer.from(digest, 'hex');
    return this.asym.verify(digest, sig, key, ph, ctx);
  }
}
