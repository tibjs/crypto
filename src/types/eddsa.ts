import {HashCtor} from './hash';
import {Asym} from './asym';

export interface EDDSAPublicKeyProps {
  x?: Buffer;
  y?: Buffer;
}

export interface EDDSAPrivateKeyProps {
  d?: Buffer;
}

export interface EDDSAPublicKeyJSON extends Required<EDDSAPublicKeyProps> {}

export interface EDDSAPrivateKeyJSON
  extends EDDSAPublicKeyJSON,
    EDDSAPrivateKeyProps {}

export interface EDDSA extends Asym<EDDSAPrivateKeyJSON, EDDSAPublicKeyJSON> {
  readonly native: number;

  readonly id: string;
  readonly type: string;
  readonly mid: string | null;
  readonly eid: string | null;
  readonly hash: HashCtor;

  readonly curve: any;
  readonly mount: any;
  readonly iso: any;
  readonly size: number;
  readonly bits: number;

  hashNonce(prefix: Buffer, msg: Buffer, ph: any, ctx: any): Buffer;

  hashChallenge(R: Buffer, A: Buffer, m: Buffer, ph: any, ctx: any): Buffer;

  privateKeyGenerate(): Buffer;

  scalarGenerate(): Buffer;

  privateKeyExpand(secret: Buffer): [Buffer, Buffer];

  privateKeyConvert(secret: Buffer): Buffer;

  privateKeyVerify(secret: Buffer): boolean;

  scalarVerify(scalar: Buffer): boolean;

  scalarIsZero(scalar: Buffer): boolean;

  scalarClamp(scalar: Buffer): Buffer;

  privateKeyExport(secret: Buffer): EDDSAPrivateKeyJSON;

  privateKeyImport(props: EDDSAPrivateKeyProps): Buffer;

  scalarTweakAdd(scalar: Buffer, tweak: Buffer): Buffer;

  scalarTweakMul(scalar: Buffer, tweak: Buffer): Buffer;

  scalarReduce(scalar: Buffer): Buffer;

  scalarNegate(scalar: Buffer): Buffer;

  scalarInvert(scalar: Buffer): Buffer;

  publicKeyCreate(secret: Buffer): Buffer;

  publicKeyFromScalar(scalar: Buffer): Buffer;

  publicKeyConvert(key: Buffer): Buffer;

  publicKeyFromUniform(key: Buffer): Buffer;

  publicKeyToUniform(key: Buffer, hint?: number): Buffer;

  publicKeyFromHash(bytes: Buffer, compress?: boolean): Buffer;

  publicKeyToHash(key: Buffer): Buffer;

  publicKeyVerify(key: Buffer): boolean;

  publicKeyIsInfinity(key: Buffer): boolean;

  publicKeyIsSmall(key: Buffer): boolean;

  publicKeyHasTorsion(key: Buffer): boolean;

  publicKeyExport(key: Buffer): EDDSAPublicKeyJSON;

  publicKeyImport(props: EDDSAPublicKeyProps): Buffer;

  publicKeyTweakAdd(key: Buffer, tweak: Buffer): Buffer;

  publicKeyTweakMul(key: Buffer, tweak: Buffer): Buffer;

  publicKeyAdd(key1: Buffer, key2: Buffer): Buffer;

  publicKeyCombine(keys: Buffer[]): Buffer;

  publicKeyNegate(key: Buffer): Buffer;

  sign(
    msg: Buffer,
    secret: Buffer,
    ph: null | boolean,
    ctx: Buffer | null,
  ): Buffer;

  signWithScalar(
    msg: Buffer,
    scalar: Buffer,
    prefix: Buffer,
    ph: null | boolean,
    ctx: Buffer,
  ): Buffer;

  signTweakAdd(
    msg: Buffer,
    secret: Buffer,
    tweak: Buffer,
    ph: null | boolean,
    ctx: Buffer,
  ): Buffer;

  signTweakMul(
    msg: Buffer,
    secret: Buffer,
    tweak: Buffer,
    ph: null | boolean,
    ctx: Buffer,
  ): Buffer;

  verify(
    msg: Buffer,
    sig: Buffer,
    key: Buffer,
    ph: null | boolean,
    ctx?: Buffer | null,
  ): boolean;

  verifySingle(
    msg: Buffer,
    sig: Buffer,
    key: Buffer,
    ph: null | boolean,
    ctx?: Buffer | null,
  ): boolean;

  verifyBatch(
    batch: [Buffer, Buffer, Buffer][],
    ph: null | boolean,
    ctx?: Buffer | null,
  ): boolean;

  derive(pub: Buffer, secret: Buffer): Buffer;

  deriveWithScalar(pub: Buffer, scalar: Buffer): Buffer;
}

export interface EDDSACtor {
  new (
    id: string,
    mid: string | null,
    eid: string | null,
    hash: HashCtor,
    pre?: string | string[],
  ): EDDSA;
}
