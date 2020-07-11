import {HashCtor} from './hash';

export interface Eb2k {
  native: number;
  derive(
    hash: HashCtor,
    pass: string | Buffer,
    salt: string | Buffer,
    keyLen: number,
    ivLen: number,
  ): [Buffer, Buffer];
}
