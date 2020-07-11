export interface Box {
  seal(msg: Buffer, pub: Buffer, priv?: Buffer): Buffer;
  open(msg: Buffer, priv: Buffer): Buffer;
}
