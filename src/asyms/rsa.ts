import {assert} from '../internal/assert';
import {Adsa, RSA, HashCtor} from '../types';

export function extend(asym: RSA): RSA {
  asym.id = asym.id || 'RSA';
  asym.algo = 'RSA';
  if (!asym.derive) {
    asym.derive = () => {
      throw new Error('Unsupported');
    };
  }
  asym.adsa = (hash?: HashCtor) => {
    assert(hash, 'hash is required for RSA sign and verify');
    return new RSAAdsa(asym, hash!);
  };
  return asym;
}

class RSAAdsa implements Adsa {
  readonly id: string;

  constructor(public asym: RSA, protected hash: HashCtor) {
    this.id = 'RSA_' + hash.id;
  }

  sign(msg: string | Buffer, key: any): Buffer {
    return this.signMessage(msg, key);
  }

  signMessage(msg: string | Buffer, key: any): Buffer {
    msg = Buffer.isBuffer(msg) ? msg : Buffer.from(msg, 'hex');
    return this.asym.sign(this.hash, this.hash.digest(msg), key);
  }

  signDigest(digest: string | Buffer, key: Buffer): Buffer {
    digest = Buffer.isBuffer(digest) ? digest : Buffer.from(digest, 'hex');
    return this.asym.sign(this.hash, digest, key);
  }

  verify(msg: string | Buffer, sig: Buffer, key: any): boolean {
    return this.verifyMessage(msg, sig, key);
  }

  verifyMessage(msg: string | Buffer, sig: Buffer, key: any): boolean {
    msg = Buffer.isBuffer(msg) ? msg : Buffer.from(msg, 'hex');
    return this.asym.verify(this.hash, this.hash.digest(msg), sig, key);
  }

  verifyDigest(digest: string | Buffer, sig: Buffer, key: Buffer): boolean {
    digest = Buffer.isBuffer(digest) ? digest : Buffer.from(digest, 'hex');
    return this.asym.verify(this.hash, digest, sig, key);
  }
}
