type RandomBytesFn = (num: number) => Buffer;
type RandomLike = RandomBytesFn | {randomBytes: RandomBytesFn};

export interface Red {}

export interface RedCtor {
  new (m: string | BN): Red;
}

export interface BN {
  words: number[];
  length: number;
  negative: number;
  red: Red;

  iadd(num: BN): this;

  iaddn(num: number): this;

  add(num: BN): BN;

  addn(num: number): BN;

  isub(num: BN): this;

  isubn(num: number): this;

  sub(num: BN): BN;

  subn(num: number): BN;

  imul(num: BN): this;

  imuln(num: number): this;

  mul(num: BN): BN;

  muln(num: number): BN;

  mulShift(num: BN, bits: number): BN;

  quorem(num: BN): [BN, BN];

  iquo(num: BN): this;

  iquon(num: number): this;

  quo(num: BN): BN;

  quon(num: number): BN;

  irem(num: BN): this;

  iremn(num: number): this;

  rem(num: BN): BN;

  remn(num: number): BN;

  remrn(num: number): number;

  divmod(num: BN): BN;

  idiv(num: BN): this;

  idivn(num: number): this;

  div(num: BN): BN;

  divn(num: number): BN;

  imod(num: BN): this;

  imodn(num: number): this;

  mod(num: BN): BN;

  modn(num: number): BN;

  modrn(num: number): BN;

  divRound(num: BN): BN;

  ipow(num: BN): this;

  ipown(num: number): this;

  pow(num: BN): BN;

  pown(num: number): BN;

  isqr(): this;

  sqr(): BN;

  rootrem(pow: number): BN;

  iroot(pow: number): this;

  root(pow: number): BN;

  isPower(pow: number): boolean;

  sqrtrem(): BN;

  isqrt(): this;

  sqrt(): BN;

  isSquare(): boolean;

  iand(num: BN): this;

  iandn(num: number): this;

  and(num: BN): BN;

  andn(num: number): BN;

  andrn(num: number): BN;

  iuand(num: BN): this;

  iuandn(num: number): this;

  uand(num: BN): BN;

  uandn(num: number): BN;

  uandrn(num: number): number;

  ior(num: BN): this;

  iorn(num: number): this;

  or(num: BN): BN;

  orn(num: number): BN;

  iuor(num: BN): this;

  iuorn(num: number): this;

  uor(num: BN): BN;

  uorn(num: number): BN;

  ixor(num: BN): this;

  ixorn(num: number): this;

  xor(num: BN): BN;

  xorn(num: number): BN;

  iuxor(num: BN): this;

  iuxorn(num: number): this;

  uxor(num: BN): BN;

  uxorn(num: number): BN;

  inot(): this;

  not(): BN;

  inotn(width: number): this;

  notn(width: number): BN;

  ishl(num: BN): this;

  ishln(bits: number): this;

  shl(num: BN): BN;

  shln(bits: number): BN;

  iushl(num: BN): this;

  iushln(bits: number): this;

  ushl(num: BN): BN;

  ushln(bits: number): BN;

  ishr(num: BN): this;

  ishrn(bits: number): this;

  shr(num: BN): BN;

  shrn(bits: number): BN;

  iushr(num: BN): this;

  iushrn(bits: number): this;

  ushr(num: BN): BN;

  ushrn(bits: number): BN;

  setn(bit: number, val: number): this;

  usetn(bit: number, val: number): this;

  testn(bit: number): BN;

  utestn(bit: number): number;

  imaskn(bits: number): this;

  maskn(bits: number): BN;

  iumaskn(bits: number): this;

  umaskn(bits: number): BN;

  andln(num: number): number;

  bit(pos: number): number;

  bits(pos: number, width: number): number;

  ineg(): this;

  neg(): BN;

  iabs(): this;

  abs(): BN;

  cmp(num: BN): number;

  cmpn(num: number): number;

  eq(num: BN): boolean;

  eqn(num: number): boolean;

  gt(num: BN): boolean;

  gtn(num: number): boolean;

  gte(num: BN): boolean;

  gten(num: number): boolean;

  lt(num: BN): boolean;

  ltn(num: number): boolean;

  lte(num: BN): boolean;

  lten(num: number): boolean;

  sign(): number;

  isZero(): boolean;

  isNeg(): boolean;

  isPos(): boolean;

  isOdd(): boolean;

  isEven(): boolean;

  ucmp(num: BN): number;

  ucmpn(num: number): number;

  legendre(num: BN): number;

  jacobi(num: BN): number;

  kronecker(num: BN): number;

  igcd(num: BN): this;

  gcd(num: BN): this;

  ilcm(num: BN): this;

  lcm(num: BN): this;

  egcd(num: BN): (BN | any)[];

  iinvert(num: BN): this;

  invert(num: BN): BN;

  ifermat(num: BN): this;

  fermat(num: BN): BN;

  ipowm(y: BN, m: BN | string, mont?: boolean): this;

  powm(y: BN, m: BN | string, mont?: boolean): BN;

  ipowmn(y: BN, m: BN | string, mont?: boolean): this;

  powmn(y: BN, m: BN | string, mont?: boolean): BN;

  isqrtm(p: BN): this;

  sqrtm(p: BN): BN;

  isqrtpq(p: BN, q: BN): this;

  sqrtpq(p: BN, q: BN): BN;

  isPrime(rng: RandomLike, reps: number, limit?: number): boolean;

  isPrimeMR(rng: RandomLike, reps: number, force2?: boolean): boolean;

  isPrimeLucas(limit?: number): boolean;

  toTwos(width: number): BN;

  fromTwos(width: number): BN;

  toRed(ctx: Red): BN;

  fromRed(): BN;

  forceRed(ctx: Red): BN;

  redIAdd(num: BN): this;

  redAdd(num: BN): BN;

  redIAddn(num: number): this;

  redAddn(num: number): BN;

  redISub(num: BN): this;

  redSub(num: BN): BN;

  redISubn(num: number): this;

  redSubn(num: number): BN;

  redIMul(num: BN): this;

  redMul(num: BN): BN;

  redIMuln(num: number): this;

  redMuln(num: number): BN;

  redIDiv(num: BN): this;

  redDiv(num: BN): BN;

  redIDivn(num: number): this;

  redDivn(num: number): BN;

  redIPow(num: BN): this;

  redPow(num: BN): BN;

  redIPown(num: number): this;

  redPown(num: number): BN;

  redISqr(): this;

  redSqr(): BN;

  redISqrt(): this;

  redSqrt(): BN;

  redIDivSqrt(v: BN): this;

  redDivSqrt(v: BN): BN;

  redIsSquare(): boolean;

  redIShl(num: BN): this;

  redShl(num: BN): BN;

  redIShln(num: number): this;

  redShln(num: number): BN;

  redINeg(): this;

  redNeg(): BN;

  redEq(num: BN): boolean;

  redEqn(num: number): boolean;

  redIsHigh(): boolean;

  redIsLow(): boolean;

  redIsOdd(): boolean;

  redIsEven(): boolean;

  redLegendre(): number;

  redJacobi(): number;

  redKronecker(): number;

  redIInvert(): this;

  redInvert(): BN;

  redIFermat(): this;

  redFermat(): BN;

  clone(): BN;

  inject(num: BN): this;

  set(num: number, endian?: string): this;

  swap(num: BN): this;

  reverse(): this;

  byteLength(): number;

  bitLength(): number;

  zeroBits(): number;

  isSafe(): boolean;

  word(pos: number): number;

  csign(): number;

  czero(): number;

  cneg(): number;

  cpos(): number;

  ceq(num: BN): number;

  ceqn(num: number): number;

  cswap(num: BN, flag: number): this;

  cinject(num: BN, flag: number): this;

  cset(num: BN, flag: number): this;

  toNumber(): number;

  toDouble(): number;

  valueOf(): number;

  toBigInt(): bigint;

  toBool(): boolean;

  toString(base?: number | string, padding?: number): string;

  toJSON(): string;

  toArray(endian?: string, length?: number): number[];

  toBuffer(endian?: string, length?: number): Buffer;

  toArrayLike<T>(ArrayType: T, endian?: string, length?: number): T;

  encode(endian?: string, length?: number): Buffer;

  of(num: number, endian?: string): this;

  fromNumber(num: number, endian?: string): this;

  fromDouble(num: number, endian?: string): this;

  fromBigInt(num: number, endian?: string): this;

  fromBool(value: boolean): this;

  fromString(str: string, base?: number | string, endian?: string): this;

  fromJSON(json: any): this;

  fromBN(num: BN): this;

  fromArray(data: number[], endian?: string): any;

  fromBuffer(data: Buffer, endian?: string): any;

  fromArrayLike(data: number | Buffer, endian?: string): any;

  decode(data: Buffer, endian?: string): this;

  from(
    num?: number | bigint | string | boolean | object,
    base?: number | string,
    endian?: string,
  ): this;
}

export interface BNCtor {
  native: number;
  wordSize: number;
  Red: RedCtor;
  new (
    num: number | bigint | string | object | boolean,
    base?: number | string,
    endian?: string,
  ): BN;
  decode(data: Buffer, endian?: string): BN;
}
