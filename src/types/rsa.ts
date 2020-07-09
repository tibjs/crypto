import {HashCtor} from './hash';
import {Asym, Adsa} from './asym';
import {BN} from './bn';

export interface RSAPublicKeyProps {
  n?: Buffer;
  e?: Buffer;
}

export interface RSAPrivateKeyProps extends RSAPublicKeyProps {
  d?: Buffer;
  p?: Buffer;
  q?: Buffer;
  dp?: Buffer;
  dq?: Buffer;
  qi?: Buffer;
}

export interface RSAPublicKeyJSON extends Required<RSAPublicKeyProps> {}

export interface RSAPrivateKeyJSON extends Required<RSAPrivateKeyProps> {}

export interface RSAPublicKey {
  n: BN;
  e: BN;

  bits(): number;

  size(): number;

  isSane(): boolean;

  verify(): boolean;

  encrypt(msg: Buffer): Buffer;

  encode(): Buffer;

  decode(data: Buffer): this;
}

export interface RSAPublicKeyCtor {
  new (): RSAPublicKey;

  decode(data: Buffer): RSAPublicKey;
}

export interface RSAPrivateKey extends RSAPublicKey {
  d: BN;
  p: BN;
  q: BN;
  dp: BN;
  dq: BN;
  qi: BN;

  decrypt(msg: Buffer): Buffer;

  generate(bits: number, exponent: number): this;

  generateAsync(bits: number, exponent: number): Promise<this>;

  fromPQE(p: BN, q: BN, e: BN): this;

  fromPQD(p: BN, q: BN, d: BN): this;

  fromNED(n: BN, e: BN, d: BN): this;

  toPublic(): RSAPublicKey;

  encode(): Buffer;

  decode(data: Buffer): this;
}

export interface RSAPrivateKeyCtor {
  new (): RSAPrivateKey;

  generate(bits: number, exponent: number): RSAPrivateKey;

  generateAsync(bits: number, exponent: number): Promise<RSAPrivateKey>;

  fromPQE(p: BN, q: BN, e: BN): RSAPrivateKey;

  fromPQD(p: BN, q: BN, d: BN): RSAPrivateKey;

  fromNED(n: BN, e: BN, d: BN): RSAPrivateKey;

  decode(data: Buffer): RSAPrivateKey;
}

export type HashParam = {id: string} | string | undefined | null;

export interface RSA extends Asym<RSAPrivateKeyJSON, RSAPublicKeyJSON> {
  readonly native: number;

  SALT_LENGTH_AUTO: number;
  SALT_LENGTH_HASH: number;

  privateKeyGenerate(bits?: number, exponent?: number): Buffer;

  privateKeyGenerateAsync(bits?: number, exponent?: number): Promise<Buffer>;

  privateKeyBits(key: Buffer): number;

  privateKeyVerify(key: Buffer): boolean;

  privateKeyImport(json: RSAPrivateKeyProps): Buffer;

  privateKeyExport(key: Buffer): RSAPrivateKeyJSON;

  publicKeyCreate(key: Buffer): Buffer;

  publicKeyBits(key: Buffer): number;

  publicKeyVerify(key: Buffer): boolean;

  publicKeyImport(raw: RSAPublicKeyProps): Buffer;

  publicKeyExport(key: Buffer): RSAPublicKeyJSON;

  sign(hash: HashParam, msg: Buffer, key: Buffer): Buffer;

  verify(hash: HashParam, msg: Buffer, sig: Buffer, key: Buffer): boolean;

  encrypt(msg: Buffer, key: Buffer): Buffer;

  decrypt(msg: Buffer, key: Buffer): Buffer;

  signPSS(hash: HashCtor, msg: Buffer, key: Buffer, saltLen?: number): Buffer;

  verifyPSS(
    hash: HashCtor,
    msg: Buffer,
    sig: Buffer,
    key: Buffer,
    saltLen?: number,
  ): boolean;

  encryptOAEP(hash: HashCtor, msg: Buffer, key: Buffer, label?: Buffer): Buffer;

  decryptOAEP(hash: HashCtor, msg: Buffer, key: Buffer, label?: Buffer): Buffer;

  veil(msg: Buffer, bits: number, key: Buffer): Buffer;

  unveil(msg: Buffer, bits: number, key: Buffer): Buffer;

  /**
   * Creates and returns a Adsa object that uses the given algorithm
   *
   * @param hash RSA signing hash algorithm
   */
  adsa(hash?: HashCtor): Adsa;
}
