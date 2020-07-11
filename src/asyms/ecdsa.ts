import {assert} from '../internal/assert';
import {Adsa, ECDSA, HashCtor} from '../types';

export function extend(asym: ECDSA): ECDSA {
  asym.algo = 'ECDSA';
  asym.adsa = (hash?: HashCtor): Adsa => new ECDSAAdsa(asym, hash);
  return asym;
}

class ECDSAAdsa implements Adsa {
  readonly id: string;

  constructor(public asym: ECDSA, protected hash?: HashCtor) {
    this.id = asym.id;
  }

  sign(msg: string | Buffer, key: Buffer): Buffer {
    return this.signMessage(msg, key);
  }

  signMessage(msg: string | Buffer, key: Buffer): Buffer {
    assert(this.hash, 'hash is required');
    msg = Buffer.isBuffer(msg) ? msg : Buffer.from(msg, 'hex');
    return this.asym.sign(this.hash!.digest(msg), key);
  }

  signDigest(digest: string | Buffer, key: Buffer): Buffer {
    digest = Buffer.isBuffer(digest) ? digest : Buffer.from(digest, 'hex');
    return this.asym.sign(digest, key);
  }

  verify(msg: string | Buffer, sig: Buffer, key: Buffer): boolean {
    return this.verifyMessage(msg, sig, key);
  }

  verifyMessage(msg: string | Buffer, sig: Buffer, key: Buffer): boolean {
    assert(this.hash, 'hash is required');
    msg = Buffer.isBuffer(msg) ? msg : Buffer.from(msg, 'hex');
    return this.asym.verify(this.hash!.digest(msg), sig, key);
  }

  verifyDigest(digest: string | Buffer, sig: Buffer, key: Buffer): boolean {
    digest = Buffer.isBuffer(digest) ? digest : Buffer.from(digest, 'hex');
    return this.asym.verify(digest, sig, key);
  }
}
