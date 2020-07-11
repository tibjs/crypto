export interface DSAPublicKeyJson {
  p: Buffer;
  q: Buffer;
  g: Buffer;
  y: Buffer;
}

export interface DSAPrivateKeyJson extends DSAPublicKeyJson {
  x: Buffer;
}

export interface DSA {
  native: number;
  paramsCreate(key: Buffer): Buffer;
  paramsGenerate(bits: number): Buffer;
  paramsGenerateAsync(bits: number): Buffer;
  paramsBits(params: Buffer): number;
  paramsScalarBits(params: Buffer): number;
  paramsVerify(params: Buffer): boolean;
  paramsImport(json: {p?: Buffer; q?: Buffer; g?: Buffer}): Buffer;
  paramsExport(params: Buffer): {p: Buffer; q: Buffer; g: Buffer};
  privateKeyCreate(params: Buffer): Buffer;
  privateKeyGenerate(bits?: number): Buffer;
  privateKeyGenerateAsync(bits?: number): Buffer;
  privateKeyBits(key: Buffer): number;
  privateKeyScalarBits(key: Buffer): number;
  privateKeyVerify(key: Buffer): boolean;
  privateKeyImport(json: Partial<DSAPrivateKeyJson>): Buffer;
  privateKeyExport(key: Buffer): DSAPrivateKeyJson;
  publicKeyCreate(key: Buffer): Buffer;
  publicKeyBits(key: Buffer): number;
  publicKeyScalarBits(key: Buffer): number;
  publicKeyVerify(key: Buffer): boolean;
  publicKeyImport(json: Partial<DSAPublicKeyJson>): Buffer;
  publicKeyExport(key: Buffer): DSAPublicKeyJson;
  signatureImport(sig: Buffer, size: number): Buffer;
  signatureExport(sig: Buffer, size: number): Buffer;
  sign(msg: Buffer, key: Buffer): Buffer;
  signDER(msg: Buffer, key: Buffer): Buffer;
  verify(msg: Buffer, sig: Buffer, key: Buffer): boolean;
  verifyDER(msg: Buffer, sig: Buffer, key: Buffer): boolean;
  derive(pub: Buffer, priv: Buffer): Buffer;
}
