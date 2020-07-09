interface HMAC {
  init(key: Buffer): this;

  update(data: Buffer): this;

  final(): Buffer;
}

export interface Hash {
  init(...arg: any[]): this;

  update(data: Buffer): this;

  final(): Buffer;
}

export interface HashCtor {
  native: number;
  id: string;
  size: number;
  bits: number;
  blockSize: number;
  zero: Buffer;
  ctx: Hash;

  new (): Hash;

  hash(): Hash;

  hmac(): HMAC;

  digest(data: Buffer, ...args: any[]): Buffer;

  root(left: Buffer, right: Buffer): Buffer;

  multi(x: Buffer, y: Buffer, z?: Buffer, ...args: any[]): Buffer;

  mac(data: Buffer, key: Buffer): Buffer;
}
