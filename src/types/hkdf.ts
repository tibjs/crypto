import {HashCtor} from './hash';

export interface HKDF {
  native: number;

  extract(hash: HashCtor, ikm?: Buffer, salt?: Buffer): Buffer;
  expand(hash: HashCtor, prk: Buffer, info: Buffer, len: number): Buffer;
  derive(
    hash: HashCtor,
    ikm: Buffer,
    salt: Buffer,
    info: Buffer,
    len: number,
  ): Buffer;
}
