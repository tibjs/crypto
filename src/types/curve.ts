export interface Curve {
  id: string;
  type: string;
  size: number;
  bits: number;

  privateKeyGenerate(key: Buffer): Buffer;

  privateKeyReduce?(key: Buffer): Buffer;
  scalarGenerate?(): Buffer;
  scalarClamp?(key: Buffer): Buffer;
}
