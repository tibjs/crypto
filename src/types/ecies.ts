import {HashCtor} from './hash';
import {Curve} from './curve';

export interface ECIES {
  encrypt(
    curve: Curve,
    kdf: HashCtor | null,
    msg: Buffer,
    pub: Buffer,
    priv?: Buffer,
  ): Buffer;
  decrypt(
    curve: Curve,
    kdf: HashCtor | null,
    msg: Buffer,
    priv: Buffer,
  ): Buffer;
}
