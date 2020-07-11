export type UnsignedValue = number | Buffer;

export interface Base16 {
  encode(data: Buffer, size?: number | null): string;
  encodeLE(data: Buffer, size?: number | null): string;
  decode(str: string, size?: number | null): Buffer;
  decodeLE(str: string, size?: number | null): Buffer;
  test(str: string, size?: number | null): boolean;
}

export interface Base32 {
  encode(data: Buffer, pad?: boolean): string;
  encodeHex(data: Buffer, pad?: boolean): string;
  decode(str: string, unpad?: boolean): Buffer;
  decodeHex(str: string, unpad?: boolean): Buffer;
  test(str: string, unpad?: boolean): boolean;
  testHex(str: string, unpad?: boolean): boolean;
}

export interface Base58 {
  native: number;
  encode(data: Buffer): string;
  decode(str: string): Buffer;
  test(str: string): boolean;
}

export interface Base64 {
  encode(data: Buffer): string;
  decode(str: string): Buffer;
  test(str: string): boolean;
  encodeURL(data: Buffer): string;
  decodeURL(str: string): Buffer;
  testURL(str: string): boolean;
}

export interface Bech32 {
  native: number;
  serialize(hrp: string, data: Buffer): string;
  deserialize(str: string): [string, Buffer];
  is(str: string): boolean;
  convertBits(
    data: Buffer,
    srcbits: number,
    dstbits: number,
    pad: boolean,
  ): Buffer;
  encode(hrp: string, version: number, hash: Buffer): string;
  decode(str: string): [string, number, Buffer];
  test(str: string): boolean;
}

export interface Cash32 {
  native: number;
  serialize(prefix: string, data: Buffer): string;
  deserialize(str: string, fallback: string): [string, Buffer];
  is(str: string, fallback: string): boolean;
  convertBits(
    data: Buffer,
    srcbits: number,
    dstbits: number,
    pad: boolean,
  ): Buffer;
  encode(prefix: string, type: number, hash: Buffer): string;
  decode(addr: string, expect?: string): [number, Buffer];
  test(addr: string, expect?: string): boolean;
}
