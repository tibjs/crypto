export interface AES {
  native: number;
  encipher(data: Buffer, key: Buffer, iv: Buffer): Buffer;
  decipher(data: Buffer, key: Buffer, iv: Buffer): Buffer;
}
