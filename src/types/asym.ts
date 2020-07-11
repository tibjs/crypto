import {HashCtor} from './hash';
import {Curve} from './curve';

/**
 * Asymmetric Digital Signature Algorithms
 */
export interface Adsa {
  readonly id: string;
  readonly asym: any;

  sign(msg: string | Buffer, key: Buffer, ...extra: any[]): Buffer;

  signMessage(msg: string | Buffer, key: Buffer, ...extra: any[]): Buffer;

  signDigest(digest: string | Buffer, key: Buffer, ...extra: any[]): Buffer;

  verify(
    msg: string | Buffer,
    sig: Buffer,
    key: Buffer,
    ...extra: any[]
  ): boolean;

  verifyMessage(
    msg: string | Buffer,
    sig: Buffer,
    key: Buffer,
    ...extra: any[]
  ): boolean;

  verifyDigest(
    digest: string | Buffer,
    sig: Buffer,
    key: Buffer,
    ...extra: any[]
  ): boolean;
}

interface KeyProps {
  [prop: string]: Buffer;
}

export interface Asym<PrivateKeyJSON, PublicKeyJSON> extends Curve {
  id: string;
  algo: string;

  // Private Key
  privateKeyGenerate(...args: any[]): Buffer;

  privateKeyVerify(key: Buffer): boolean;

  privateKeyExport(key: Buffer, compress?: boolean): PrivateKeyJSON;

  privateKeyImport(json: KeyProps): Buffer;

  // Public Key
  publicKeyCreate(key: Buffer, compress?: boolean): Buffer;

  publicKeyConvert?(key: Buffer, compress?: boolean): Buffer;

  publicKeyFromUniform(key: Buffer, compress?: boolean): Buffer;

  publicKeyToUniform(key: Buffer, hint?: number): Buffer;

  publicKeyFromHash(bytes: Buffer, compress?: boolean): Buffer;

  publicKeyToHash(key: Buffer): Buffer;

  publicKeyVerify(key: Buffer): boolean;

  publicKeyExport(key: Buffer): PublicKeyJSON;

  publicKeyImport(raw: KeyProps, compress?: boolean): Buffer;

  // Key Derive
  /**
   *
   * @param pubkey
   * @param privkey
   * @param [compress] Only for EC algorithm
   */
  derive(pubkey: Buffer, privkey: Buffer, compress?: boolean): Buffer;

  // ADSA
  adsa(hash?: HashCtor): Adsa;
}
