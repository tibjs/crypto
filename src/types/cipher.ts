export interface AeadOptions {
  msgLen?: number;
  tagLen?: number;
  aad?: Buffer;
}

export interface CipherBase {
  readonly encrypt: boolean;

  init(key: Buffer, iv?: Buffer): this;

  setAead(options?: AeadOptions): this;

  update(data: Buffer): Buffer;

  crypt(output: Buffer, input: Buffer): Buffer;

  final(): Buffer;

  destroy(): this;

  setAutoPadding(padding: boolean): this;

  setAAD(data: Buffer): this;

  setCCM(msgLen: number, tagLen: number, aad?: Buffer): this;

  getAuthTag(): Buffer;

  setAuthTag(tag: Buffer): this;
}

export interface CipherBaseCtor {
  new (name: string, encrypt: boolean): CipherBase;
}

export interface Cipher extends CipherBase {}

export interface CipherCtor extends CipherBaseCtor {
  new (name: string): Cipher;
}

export interface Decipher extends CipherBase {}

export interface DecipherCtor extends CipherBaseCtor {
  new (name: string): Decipher;
}

export interface Encrypt {
  (
    name: string,
    key: Buffer,
    iv: Buffer,
    data: Buffer,
    tagLen?: number,
  ): Buffer;
}

export interface Decrypt {
  (
    name: string,
    key: Buffer,
    iv: Buffer,
    data: Buffer,
    tagOrLen?: number | Buffer,
  ): Buffer;
}

export interface CipherExports {
  native: number;
  Cipher: CipherCtor;
  Decipher: DecipherCtor;
  encrypt: Encrypt;
  decrypt: Decrypt;
}
