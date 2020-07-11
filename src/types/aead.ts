export interface AEAD {
  init(key: Buffer, iv: Buffer): this;
  aad(data: Buffer): this;
  encrypt(data: Buffer): Buffer;
  decrypt(data: Buffer): Buffer;
  auth(data: Buffer): Buffer;
  final(): Buffer;
  destroy(): this;
  verify(tag: Buffer): boolean;
}

export interface AEADCtor {
  native: number;
  new (): AEAD;
  encrypt(key: Buffer, iv: Buffer, msg: Buffer, aad?: Buffer): Buffer;
  decrypt(
    key: Buffer,
    iv: Buffer,
    msg: Buffer,
    tag: Buffer,
    aad?: Buffer,
  ): Buffer;
  auth(key: Buffer, iv: Buffer, msg: Buffer, tag: Buffer, aad?: Buffer): Buffer;
}
