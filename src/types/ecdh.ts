import {Curve} from './curve';

export interface ECDHPublicKeyProps {
  x: Buffer;
  y?: Buffer;
}

export interface ECDHPrivateKeyProps {
  d: Buffer;
}

export interface ECDHPublicKeyJSON extends Required<ECDHPublicKeyProps> {}

export interface ECDHPrivateKeyJSON
  extends ECDHPublicKeyJSON,
    ECDHPrivateKeyProps {}

export interface ECDH extends Curve {
  readonly native: number;
  readonly id: string;
  readonly type: string;
  readonly eid: string | null;

  readonly curve: any;
  readonly edwards: any;
  readonly size: number;
  readonly bits: number;

  privateKeyGenerate(): Buffer;

  privateKeyVerify(key: Buffer): boolean;

  privateKeyExport(key: Buffer, sign?: boolean): ECDHPrivateKeyJSON;

  privateKeyImport(props: ECDHPrivateKeyProps): Buffer;

  publicKeyCreate(key: Buffer): Buffer;

  publicKeyConvert(key: Buffer, sign: boolean): Buffer;

  publicKeyFromUniform(key: Buffer): Buffer;

  publicKeyToUniform(key: Buffer, hint?: number): Buffer;

  publicKeyFromHash(bytes: Buffer, compress?: boolean): Buffer;

  publicKeyToHash(key: Buffer): Buffer;

  publicKeyVerify(key: Buffer): boolean;

  publicKeyIsSmall(key: Buffer): boolean;

  publicKeyHasTorsion(key: Buffer): boolean;

  publicKeyExport(key: Buffer, sign?: boolean): ECDHPublicKeyJSON;

  publicKeyImport(props: ECDHPublicKeyProps): Buffer;

  publicKeyTweakAdd(key: Buffer, tweak: Buffer): Buffer;

  publicKeyTweakMul(key: Buffer, tweak: Buffer): Buffer;

  publicKeyAdd(key1: Buffer, key2: Buffer): Buffer;

  publicKeyCombine(keys: Buffer[]): Buffer;

  publicKeyNegate(key: Buffer): Buffer;

  derive(pub: Buffer, secret: Buffer): Buffer;
}
