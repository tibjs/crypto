export interface ARC4 {
  init(key: Buffer): this;
  encrypt(data: Buffer): Buffer;
  destroy(): this;
}

export interface ARC4Ctor {
  native: number;
  new (): ARC4;
}
