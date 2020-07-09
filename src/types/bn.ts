export interface BN {
  add(num: BN): BN;

  encode(endian?: string, length?: number): Buffer;
}

export interface Red {}

export interface RedCtor {
  new (m: string | BN): Red;
}

export interface BNCtor {
  Red: RedCtor;
  new (
    num: number | bigint | string | object | boolean,
    base?: number | string,
    endian?: string,
  ): BN;
  decode(data: Buffer, endian?: string): BN;
}
