import {HashCtor} from './hash';
import {Asym} from './asym';

export interface ECDSAPublicKeyProps {
  x?: Buffer;
  y?: Buffer;
}

export interface ECDSAPrivateKeyProps {
  d?: Buffer;
}

export interface ECDSAPublicKeyJSON extends Required<ECDSAPublicKeyProps> {}

export interface ECDSAPrivateKeyJSON
  extends ECDSAPublicKeyJSON,
    ECDSAPrivateKeyProps {}

export interface ECDSA extends Asym<ECDSAPrivateKeyJSON, ECDSAPublicKeyJSON> {
  readonly native: number;
  readonly id: string;
  readonly type: string;
  readonly hash: HashCtor;

  readonly curve: any;
  readonly schnorr: any;
  readonly size: number;
  readonly bits: number;

  privateKeyGenerate(): Buffer;

  privateKeyVerify(key: Buffer): boolean;

  privateKeyExport(key: Buffer): ECDSAPrivateKeyJSON;

  privateKeyImport(json: ECDSAPrivateKeyProps): Buffer;

  privateKeyTweakAdd(key: Buffer, tweak: Buffer): Buffer;

  privateKeyTweakMul(key: Buffer, tweak: Buffer): Buffer;

  privateKeyReduce(key: Buffer): Buffer;

  privateKeyNegate(key: Buffer): Buffer;

  privateKeyInvert(key: Buffer): Buffer;

  publicKeyCreate(key: Buffer, compress?: boolean): Buffer;

  publicKeyConvert(key: Buffer, compress?: boolean): Buffer;

  publicKeyFromUniform(key: Buffer, compress?: boolean): Buffer;

  publicKeyToUniform(key: Buffer, hint?: number): Buffer;

  publicKeyFromHash(bytes: Buffer, compress?: boolean): Buffer;

  publicKeyToHash(key: Buffer): Buffer;

  publicKeyVerify(key: Buffer): boolean;

  publicKeyExport(key: Buffer): ECDSAPublicKeyJSON;

  publicKeyImport(json: ECDSAPublicKeyProps, compress?: boolean): Buffer;

  publicKeyTweakAdd(key: Buffer, tweak: Buffer, compress?: boolean): Buffer;

  publicKeyTweakMul(key: Buffer, tweak: Buffer, compress?: boolean): Buffer;

  publicKeyCombine(keys: Buffer[], compress?: boolean): Buffer;

  publicKeyNegate(key: Buffer, compress?: boolean): Buffer;

  signatureNormalize(sig: Buffer): Buffer;

  signatureNormalizeDER(sig: Buffer): Buffer;

  signatureExport(sig: Buffer): Buffer;

  signatureImport(sig: Buffer): Buffer;

  isLowS(sig: Buffer): boolean;

  isLowDER(sig: Buffer): boolean;

  sign(msg: Buffer, key: Buffer): Buffer;

  signRecoverable(msg: Buffer, key: Buffer): [Buffer, number];

  signDER(msg: Buffer, key: Buffer): Buffer;

  signRecoverableDER(msg: Buffer, key: Buffer): [Buffer, number];

  verify(msg: Buffer, sig: Buffer, key: Buffer): boolean;

  verifyDER(msg: Buffer, sig: Buffer, key: Buffer): boolean;

  recover(msg: Buffer, sig: Buffer, param: number, compress?: boolean): Buffer;

  recoverDER(
    msg: Buffer,
    sig: Buffer,
    param: number,
    compress?: boolean,
  ): Buffer;

  derive(pub: Buffer, priv: Buffer, compress?: boolean): Buffer;

  schnorrSign(msg: Buffer, key: Buffer): Buffer;

  schnorrVerify(msg: Buffer, sig: Buffer, key: Buffer): boolean;

  schnorrVerifyBatch(batch: [Buffer, Buffer, Buffer][]): boolean;
}

export interface ECDSACtor {
  new (name: string, hash: HashCtor, pre?: string | string[]): ECDSA;
}
