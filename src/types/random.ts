export interface Random {
  native: number;

  /**
   * Generate pseudo-random bytes.
   * @param {Number} size
   * @returns {Buffer}
   */
  randomBytes(size: number): Buffer;

  /**
   * Generate pseudo-random bytes.
   * @param {Buffer} data
   * @param {Number} [off=0]
   * @param {Number} [size=data.length-off]
   * @returns {Buffer}
   */
  randomFill(data: Buffer, off?: number, size?: number): Buffer;

  /**
   * Generate a random uint32.
   * @returns {Number}
   */
  randomInt(): number;

  /**
   * Generate a random uint32 within a range.
   * @param {Number} min - Inclusive.
   * @param {Number} max - Exclusive.
   * @returns {Number}
   */

  randomRange(min: number, max: number): number;
}

// export interface CtrDRBG {
//   id: string;
//   keySize: number;
//   blkSize: number;
//   entSize: number;
//   rounds: number;
//   V: Buffer;
//
//   init(entropy: Buffer, nonce?: Buffer | null, pers?: Buffer | null): this;
//
//   reseed(entropy: Buffer, add?: Buffer): this;
//
//   generate(len: number, add?: Buffer): Buffer;
//
//   update(seed?: Buffer): this;
//
//   serialize(...input: Buffer[]): Buffer;
//
//   derive(...input: Buffer[]): Buffer;
// }
//
// export interface CtrDRBGCtor {
//   native: number;
//
//   new(
//     name: string,
//     entropy?: Buffer | null,
//     nonce?: Buffer | null,
//     pers?: Buffer | null,
//     derivation?: boolean,
//   ): CtrDRBG;
// }
