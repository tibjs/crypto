/*!
 * asn1.js - ASN1 encoding for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/asn1.js:
 *   Copyright Fedor Indutny, 2013.
 *   https://github.com/indutny/asn1.js
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One
 *   https://en.wikipedia.org/wiki/X.690#BER_encoding
 *   https://en.wikipedia.org/wiki/X.690#DER_encoding
 *   http://luca.ntop.org/Teaching/Appunti/asn1.html
 *   ftp://ftp.rsasecurity.com/pub/pkcs/ascii/layman.asc
 *   https://tools.ietf.org/html/rfc2560
 *   https://tools.ietf.org/html/rfc5280
 *   https://github.com/indutny/asn1.js/blob/master/rfc/2560/index.js
 *   https://github.com/indutny/asn1.js/blob/master/rfc/5280/index.js
 *   https://github.com/indutny/asn1.js/blob/master/lib/asn1/base/node.js
 *   https://github.com/indutny/asn1.js/blob/master/lib/asn1/encoders/der.js
 *   https://github.com/indutny/asn1.js/blob/master/lib/asn1/decoders/der.js
 *   https://github.com/openssl/openssl/blob/master/include/openssl/asn1.h
 *   https://github.com/golang/go/blob/master/src/encoding/asn1/asn1.go
 *   https://github.com/golang/go/blob/master/src/encoding/asn1/marshal.go
 */

import * as bio from '@artlab/bufio';
import {BufferReader, StaticWriter, Struct} from '@artlab/bufio';
import {oids} from './oids';
import {assert} from '../internal/assert';

export namespace asn1 {
  /*
   * Constants
   */

  export const EMPTY = Buffer.alloc(0);
  export const ZERO = Buffer.alloc(1, 0x00);
  export const EMPTY_OID = new Uint32Array(2);
  export const MIN_TIME = -62167219200; // 0000-01-01T00:00:00.000Z
  export const MAX_TIME = 253402300799; // 9999-12-31T23:59:59.000Z
  export const MIN_OFFSET = -43200; // UTC-12:00
  export const MAX_OFFSET = 50400; // UTC+14:00

  // Missing types:
  //   EOC: 0
  //   OBJDESC: 7
  //   EXTERNAL: 8
  //   REAL: 9
  //   EMBED: 11
  //   ROID: 13
  //   VIDEOSTRING: 21
  //   GRAPHSTRING: 25
  //   ISO64STRING: 26
  //   UNISTRING: 28
  //   CHARSTRING: 29
  //   BMPSTRING: 30

  export const types = {
    BOOLEAN: 1,
    INTEGER: 2,
    BITSTRING: 3,
    OCTSTRING: 4,
    NULL: 5,
    OID: 6,
    ENUM: 10,
    UTF8STRING: 12,
    SEQUENCE: 16,
    SET: 17,
    NUMSTRING: 18,
    PRINTSTRING: 19,
    T61STRING: 20,
    IA5STRING: 22,
    UTCTIME: 23,
    GENTIME: 24,
    GENSTRING: 27,
  };

  export const typesByVal = {
    1: 'BOOLEAN',
    2: 'INTEGER',
    3: 'BITSTRING',
    4: 'OCTSTRING',
    5: 'NULL',
    6: 'OID',
    10: 'ENUM',
    12: 'UTF8STRING',
    16: 'SEQUENCE',
    17: 'SET',
    18: 'NUMSTRING',
    19: 'PRINTSTRING',
    20: 'T61STRING',
    22: 'IA5STRING',
    23: 'UTCTIME',
    24: 'GENTIME',
    27: 'GENSTRING',
  };

  export const classes = {
    UNIVERSAL: 0,
    APPLICATION: 1,
    CONTEXT: 2,
    PRIVATE: 3,
  };

  export const classesByVal = {
    0: 'UNIVERSAL',
    1: 'APPLICATION',
    2: 'CONTEXT',
    3: 'PRIVATE',
  };

  export const TARGET = 0xff;
  export const OPTIONAL = 1 << 8;
  export const MODE = 0xff << 9;
  export const NORMAL = 0 << 9;
  export const EXPLICIT = 1 << 9;
  export const IMPLICIT = 2 << 9;

  /**
   * Node
   */

  export class Node extends Struct {
    flags: number;
    type: number;
    raw?: Buffer | null;
    value: any;

    constructor() {
      super();
      this.flags = 0;
    }

    get mode() {
      return this.flags & MODE;
    }

    set mode(value) {
      this.flags &= ~MODE;
      this.flags |= value;
    }

    get opt() {
      return (this.flags & OPTIONAL) !== 0;
    }

    set opt(value) {
      if (value) this.flags |= OPTIONAL;
      else this.flags &= ~OPTIONAL;
    }

    get target() {
      return this.flags & TARGET;
    }

    set target(value) {
      this.flags &= ~TARGET;
      this.flags |= value;
    }

    get isRaw() {
      return false;
    }

    explicit(target: number) {
      assert(target >>> 0 === target);
      this.mode = EXPLICIT;
      this.target = target;
      return this;
    }

    implicit(target: number) {
      assert(target >>> 0 === target);
      this.mode = IMPLICIT;
      this.target = target;
      return this;
    }

    optional(value = true) {
      assert(typeof value === 'boolean');
      this.opt = value;
      return this;
    }

    clean() {
      return false;
    }

    getBodySize(extra?: any) {
      return 0;
    }

    writeBody(bw: bio.StaticWriter, extra?: any): bio.StaticWriter {
      return bw;
    }

    readBody(br: BufferReader, extra?: any): this {
      return this;
    }

    encodeBody(extra?: any) {
      const size = this.getBodySize();
      const bw = bio.write(size);
      this.writeBody(bw, extra);
      return bw.render();
    }

    decodeBody(data: Buffer, extra?: any) {
      const br = bio.read(data);
      return this.readBody(br, extra);
    }

    set(...args: any[]): this {
      return this;
    }

    from(options?: any, ...extra: any[]): this {
      if (options == null) return this;

      return this.set(options, ...extra);
    }

    error(str: string) {
      if (this.opt) return this;

      const err = new Error(str);

      if (Error.captureStackTrace) Error.captureStackTrace(err, this.error);

      throw err;
    }

    getSize(extra?: any) {
      if (this.opt && this.clean()) return 0;

      const body = this.getBodySize(extra);

      let size = 0;

      size += sizeHeader(body);
      size += body;

      if (this.mode === EXPLICIT) size += sizeHeader(size);

      return size;
    }

    write(bw: bio.StaticWriter, extra?: any) {
      if (this.opt && this.clean()) return bw;

      const body = this.getBodySize();

      switch (this.mode) {
        case EXPLICIT: {
          const size = sizeHeader(body) + body;
          writeHeader(bw, this.target, classes.CONTEXT, false, size);
        }
        // fall through
        case NORMAL: {
          const primitive =
            this.type !== types.SEQUENCE && this.type !== types.SET;
          writeHeader(bw, this.type, classes.UNIVERSAL, primitive, body);
          break;
        }
        case IMPLICIT: {
          const primitive =
            this.type !== types.SEQUENCE && this.type !== types.SET;
          writeHeader(bw, this.target, classes.CONTEXT, primitive, body);
          break;
        }
        default: {
          throw new Error('Invalid mode.');
        }
      }
      return this.writeBody(bw, extra);
    }

    read(br: BufferReader, extra?: any) {
      switch (this.mode) {
        case EXPLICIT: {
          const hdr = peekHeader(br, this.opt);

          if (!hdr) return this;

          if (hdr.cls !== classes.CONTEXT)
            return this.error(`Unexpected class: ${hdr.cls}.`);

          if (hdr.primitive) return this.error('Unexpected primitive flag.');

          if (hdr.type !== this.target)
            return this.error(`Unexpected type: ${hdr.type}.`);

          br.seek(hdr.len);
          br = br.readChild(hdr.size);
        }
        // fall through
        case NORMAL: {
          const hdr = peekHeader(br, this.opt);

          if (!hdr) return this;

          if (hdr.cls !== classes.UNIVERSAL)
            return this.error(`Unexpected class: ${hdr.cls}.`);

          const primitive =
            this.type !== types.SEQUENCE && this.type !== types.SET;

          if (hdr.primitive !== primitive)
            return this.error('Unexpected primitive flag.');

          if (hdr.type !== this.type)
            return this.error(`Unexpected type: ${hdr.type}.`);

          if (this.isRaw) {
            const size = hdr.len + hdr.size;

            this.raw = br.readBytes(size);

            br.seek(-size);
          }

          br.seek(hdr.len);

          const child = br.readChild(hdr.size);

          return this.readBody(child, extra);
        }

        case IMPLICIT: {
          const hdr = peekHeader(br, this.opt);

          if (!hdr) return this;

          if (hdr.cls !== classes.CONTEXT)
            return this.error(`Unexpected class: ${hdr.cls}.`);

          const primitive =
            this.type !== types.SEQUENCE && this.type !== types.SET;

          if (hdr.primitive !== primitive)
            return this.error('Unexpected primitive flag.');

          if (hdr.type !== this.target)
            return this.error(`Unexpected type: ${hdr.type}.`);

          br.seek(hdr.len);

          const child = br.readChild(hdr.size);

          return this.readBody(child, extra);
        }

        default: {
          throw new Error('Invalid mode.');
        }
      }
    }

    fromArray(value: any[]) {
      return this;
    }

    fromNumber(num: number) {
      return this;
    }

    fromPEM(str: string) {
      return this;
    }

    static decodeBody<T = Node>(value: Buffer): T {
      return <T>(<unknown>new this().decodeBody(value));
    }

    static fromArray<T = Node>(value: any[]): T {
      return <T>(<unknown>new this().fromArray(value));
    }

    static fromNumber<T = Node>(num: number): T {
      return <T>(<unknown>new this().fromNumber(num));
    }

    static fromPEM<T = Node>(str: string): T {
      return <T>(<unknown>new this().fromPEM(str));
    }

    static read<T = Node>(br: BufferReader, extra?: any): T {
      return <T>(<unknown>new this().read(br, extra));
    }

    static decode<T = Node>(data: Buffer, extra?: any): T {
      return <T>(<unknown>new this().decode(data, extra));
    }

    static fromHex<T = Node>(str: string, extra?: any): T {
      return <T>(<unknown>new this().fromHex(str, extra));
    }

    static fromBase64<T = Node>(str: string, extra?: any): T {
      return <T>(<unknown>new this().fromBase64(str, extra));
    }

    static fromString<T = Node>(str: string, extra?: any): T {
      return <T>(<unknown>new this().fromString(str, extra));
    }

    static fromJSON<T = Node>(json: any, extra?: any): T {
      return <T>(<unknown>new this().fromJSON(json, extra));
    }

    static fromOptions<T = Node>(options: any, extra?: any): T {
      return <T>(<unknown>new this().fromOptions(options, extra));
    }

    static from<T = Node>(options: any, extra?: any): T {
      return <T>(<unknown>new this().from(options, extra));
    }
  }

  /**
   * Sequence
   */

  export class Sequence extends Node {
    constructor(...options: any[]) {
      super();
      this.raw = null;
      this.from(...options);
    }

    get type() {
      return types.SEQUENCE;
    }
  }

  /**
   * Set
   */

  export class Set extends Node {
    constructor(...options: any[]) {
      super();
      this.raw = null;
      this.from(...options);
    }

    get type() {
      return types.SET;
    }
  }

  /**
   * Any
   */

  export class Any extends Node {
    node: Node;

    constructor(value?: Node, ...options: any[]) {
      super();
      this.node = new Null();
      this.raw = null;
      this.from(value, ...options);
    }

    get isRaw() {
      return true;
    }

    explicit(target: number): this {
      throw new Error('Cannot set explicit on any.');
    }

    implicit(target: number): this {
      throw new Error('Cannot set implicit on any.');
    }

    get type() {
      return this.node.type;
    }

    getSize(extra?: any) {
      this.node.flags = this.flags;
      return this.node.getSize(extra);
    }

    write(bw: bio.StaticWriter, extra?: any) {
      assert(bw);
      assert(this.mode === NORMAL);
      this.node.flags = this.flags;
      this.node.write(bw, extra);
      return bw;
    }

    read(br: BufferReader, extra?: any) {
      assert(br);
      assert(this.mode === NORMAL);

      const hdr = peekHeader(br, this.opt);

      if (!hdr) {
        this.node.flags = this.flags;
        return this;
      }

      const NodeClass = typeToClass(hdr.type);

      this.node = new NodeClass();
      this.node.flags = this.flags;
      this.node.read(br, extra);

      return this;
    }

    getBodySize(extra?: any) {
      this.node.flags = this.flags;
      return this.node.getBodySize(extra);
    }

    writeBody(bw: bio.StaticWriter, extra?: any) {
      this.node.flags = this.flags;
      this.node.writeBody(bw, extra);
      return bw;
    }

    readBody(br: BufferReader, extra?: any) {
      this.node.flags = this.flags;
      this.node.readBody(br, extra);
      return this;
    }

    set(node?: Node | null) {
      if (node == null) node = new Null();

      assert(node instanceof Node);

      this.node = node;
      this.node.flags = this.flags;

      return this;
    }

    clean() {
      return this.node.type === types.NULL;
    }

    format() {
      return {
        type: this.constructor.name,
        node: this.node,
      };
    }
  }

  /**
   * Choice
   */

  export class Choice extends Node {
    node: Node;

    constructor(node: Node, ...options: any[]) {
      super();
      assert(node instanceof Node);
      this.node = node;
      this.from(...options);
    }

    get type() {
      return this.node.type;
    }

    choices(): number[] {
      throw new Error('Unimplemented.');
    }

    getSize(extra?: any) {
      return this.node.getSize(extra);
    }

    write(bw: bio.StaticWriter, extra?: any) {
      assert(bw);
      this.node.flags = this.flags;
      this.node.write(bw, extra);
      return bw;
    }

    read(br: BufferReader, extra?: any) {
      assert(br);

      const choices = this.choices();

      assert(Array.isArray(choices));
      assert(choices.length >= 1);

      const hdr = peekHeader(br, this.opt);

      if (!hdr) return this;

      if (choices.indexOf(hdr.type) === -1)
        throw new Error(`Could not satisfy choice for: ${hdr.type}.`);

      const NodeClass = typeToClass(hdr.type);
      const el = new NodeClass();
      el.flags = this.flags;

      this.node = el.read(br, extra);

      return this;
    }

    getBodySize(extra?: any) {
      return this.node.getBodySize(extra);
    }

    writeBody(bw: bio.StaticWriter, extra?: any) {
      this.node.writeBody(bw, extra);
      return bw;
    }

    readBody(br: BufferReader, extra?: any) {
      this.node.readBody(br, extra);
      return this;
    }

    set(...options: any[]): this {
      return <any>this.node.set(...options);
    }

    clean() {
      return this.node.clean();
    }

    format() {
      return {
        type: this.constructor.name,
        node: this.node,
      };
    }
  }

  /**
   * String
   */
  export type String = Str;

  export class Str extends Node {
    value: string;

    constructor(...options: any[]) {
      super();
      this.value = '';
      this.from(...options);
    }

    get encoding(): BufferEncoding {
      return 'binary';
    }

    getBodySize() {
      return Buffer.byteLength(this.value, this.encoding);
    }

    writeBody(bw: bio.StaticWriter) {
      bw.writeString(this.value, this.encoding);
      return bw;
    }

    readBody(br: bio.BufferReader): this {
      const str = br.readString(br.left(), this.encoding);

      switch (this.type) {
        case types.NUMSTRING: {
          if (!isNumString(str)) throw new Error('Invalid num string.');
          break;
        }

        case types.PRINTSTRING: {
          if (!isPrintString(str)) throw new Error('Invalid print string.');
          break;
        }

        case types.IA5STRING: {
          if (!isIA5String(str)) throw new Error('Invalid print string.');
          break;
        }
      }

      this.value = str;

      return this;
    }

    set(value?: string | null) {
      if (value == null) value = '';

      assert(typeof value === 'string');

      this.value = value;

      return this;
    }

    clean() {
      return this.value.length === 0;
    }

    format() {
      return `<${this.constructor.name}: ${this.value}>`;
    }
  }

  /**
   * Boolean
   */
  export type Boolean = Bool;

  export class Bool extends Node {
    value: boolean;

    constructor(...options: any[]) {
      super();
      this.value = false;
      this.from(...options);
    }

    get type() {
      return types.BOOLEAN;
    }

    getBodySize() {
      return 1;
    }

    writeBody(bw: bio.StaticWriter) {
      bw.writeU8(this.value ? 0xff : 0x00);
      return bw;
    }

    readBody(br: bio.BufferReader) {
      if (br.left() !== 1) throw new Error('Non-minimal boolean.');

      const value = br.readU8();

      if (value !== 0x00 && value !== 0xff) throw new Error('Invalid boolean.');

      this.value = value === 0xff;

      return this;
    }

    set(value?: boolean | null) {
      if (value == null) value = false;

      assert(typeof value === 'boolean');

      this.value = value;

      return this;
    }

    clean() {
      return this.value === false;
    }

    format() {
      return `<${this.constructor.name}: ${this.value}>`;
    }
  }

  /**
   * Integer
   */

  export class Integer extends Node {
    value: Buffer;
    negative: boolean;

    constructor(value?: number | Buffer, ...options: any[]) {
      super();
      this.value = ZERO;
      this.negative = false;
      this.from(value, ...options);
    }

    get type() {
      return types.INTEGER;
    }

    getBodySize() {
      const b = this.value;

      if (b.length === 0) return 1;

      let pad = 0;
      let size = 0;

      if (!this.negative && b[0] > 127) {
        pad = 1;
      } else if (this.negative) {
        if (b[0] > 128) {
          pad = 1;
        } else if (b[0] === 128) {
          pad = 0;
          for (let i = 1; i < b.length; i++) pad |= b[i];
          pad = pad ? 1 : 0;
        }
      }

      size += pad;
      size += b.length;

      return size;
    }

    writeBody(bw: bio.StaticWriter): StaticWriter {
      const b = this.value;

      if (b.length === 0) {
        bw.writeU8(0x00);
        return bw;
      }

      let pad = 0;
      let pb = 0;

      if (!this.negative && b[0] > 127) {
        pad = 1;
        pb = 0;
      } else if (this.negative) {
        pb = 0xff;
        if (b[0] > 128) {
          pad = 1;
        } else if (b[0] === 128) {
          pad = 0;
          for (let i = 1; i < b.length; i++) pad |= b[i];
          pb = pad !== 0 ? 0xff : 0;
          pad = pb & 1;
        }
      }

      if (pad) bw.writeU8(pb);

      const start = bw.offset;

      bw.writeBytes(b);

      if (pb) twosComplement(bw.data, start, bw.offset);

      return bw;
    }

    readBody(br: bio.BufferReader) {
      let p = br.readBytes(br.left());

      if (p.length === 0) throw new Error('Zero length integer.');

      const neg = p[0] & 0x80;

      if (p.length === 1) {
        if (neg) p[0] = (p[0] ^ 0xff) + 1;

        this.negative = neg !== 0;
        this.value = p;

        return this;
      }

      if (p[0] === 0x00 && (p[1] & 0x80) === 0)
        throw new Error('Non-minimal integer.');

      if (p[0] === 0xff && (p[1] & 0x80) === 0x80)
        throw new Error('Non-minimal integer.');

      let pad = 0;

      if (p[0] === 0x00) {
        pad = 1;
      } else if (p[0] === 0xff) {
        for (let i = 1; i < p.length; i++) pad |= p[i];
        pad = pad !== 0 ? 1 : 0;
      }

      if (pad && neg === (p[1] & 0x80))
        throw new Error('Invalid integer padding.');

      if (pad) p = p.slice(1);

      if (neg) twosComplement(p, 0, p.length);

      this.negative = neg !== 0;
      this.value = trimLeft(p);

      return this;
    }

    set(value: number | Buffer, negative?: boolean) {
      if (typeof value === 'number') return this.fromNumber(value);

      if (value == null) value = ZERO;

      assert(Buffer.isBuffer(value));

      this.value = trimLeft(value);
      this.negative = false;

      if (negative != null) {
        assert(typeof negative === 'boolean');
        this.negative = negative;
      }

      return this;
    }

    clean() {
      return !this.negative && this.value.equals(ZERO);
    }

    formatValue() {
      return this.value.toString('hex');
    }

    toNumber() {
      let num = bio.readUBE(this.value, 0, this.value.length);

      if (this.negative) num = -num;

      return num;
    }

    fromNumber(num: number) {
      assert(Number.isSafeInteger(num));

      const buf = Buffer.alloc(8);

      let neg = false;

      if (num < 0) {
        neg = true;
        num = -num;
      }

      bio.writeU64BE(buf, num, 0);

      this.value = trimLeft(buf);
      this.negative = neg;

      return this;
    }

    format() {
      const name = this.constructor.name;

      if (this.value.length <= 6) return `<${name}: ${this.toNumber()}>`;

      const sign = this.negative ? '-' : '';
      const hex = this.value.toString('hex');

      return `<${name}: ${sign}0x${hex}>`;
    }
  }

  /**
   * Unsigned
   */

  export class Unsigned extends Integer {
    constructor(value?: number | Buffer, ...options: any[]) {
      super(value, ...options);
    }

    getBodySize() {
      assert(!this.negative);
      return super.getBodySize();
    }

    writeBody(bw: bio.StaticWriter) {
      assert(!this.negative);
      return super.writeBody(bw);
    }

    readBody(br: bio.BufferReader) {
      super.readBody(br);
      assert(!this.negative);
      return this;
    }

    set(value: number | Buffer) {
      return super.set(value);
    }

    toNumber() {
      assert(!this.negative);
      return super.toNumber();
    }

    fromNumber(num: number) {
      super.fromNumber(num);
      assert(!this.negative);
      return this;
    }
  }

  /**
   * BitString
   */

  export class BitString extends Node {
    bits: number;
    value: Buffer;

    constructor(value?: number | Buffer, ...options: any[]) {
      super();
      this.bits = 0;
      this.value = EMPTY;
      this.from(value, ...options);
    }

    get type() {
      return types.BITSTRING;
    }

    getBodySize() {
      return 1 + this.value.length;
    }

    writeBody(bw: bio.StaticWriter) {
      const prefix = (8 - (this.bits & 7)) & 7;
      bw.writeU8(prefix);
      bw.writeBytes(this.value);
      return bw;
    }

    readBody(br: bio.BufferReader) {
      const data = br.readBytes(br.left());

      if (data.length === 0) throw new Error('Zero length bit string.');

      const padding = data[0];

      if (
        padding > 7 ||
        (data.length === 1 && padding > 0) ||
        (data[data.length - 1] & ((1 << padding) - 1)) !== 0
      ) {
        throw new Error('Invalid padding bits.');
      }

      this.bits = (data.length - 1) * 8 - padding;
      this.value = data.slice(1);

      return this;
    }

    rightAlign() {
      const data = this.value;
      const shift = 8 - (this.bits & 7);

      if (shift === 8 || data.length === 0) return data;

      const out = Buffer.alloc(data.length);

      out[0] = data[0] >>> shift;

      for (let i = 1; i < data.length; i++) {
        out[i] = data[i - 1] << (8 - shift);
        out[i] |= data[i] >>> shift;
      }

      return out;
    }

    getBit(i: number) {
      assert(i >>> 0 === i);

      if (i < 0 || i > this.bits) return 0;

      const x = i >>> 3;
      const y = 7 - (i & 7);

      return (this.value[x] >>> y) & 1;
    }

    setBit(i: number, val: any) {
      assert(i >>> 0 === i);

      if (i < 0 || i > this.bits) return this;

      const x = i >>> 3;
      const y = 7 - (i & 7);

      if (val) this.value[x] |= 1 << y;
      else this.value[x] &= ~(1 << y);

      return this;
    }

    set(value?: number | Buffer | null) {
      if (value == null) value = EMPTY;

      if (typeof value === 'number') {
        assert(value >>> 0 === value);
        this.bits = value;
        this.value = Buffer.alloc((value + 7) >>> 3);
      } else {
        assert(Buffer.isBuffer(value));
        this.bits = value.length * 8;
        this.value = value;
      }

      return this;
    }

    clean() {
      return this.bits === 0 && this.value.length === 0;
    }

    format() {
      let value = this.rightAlign();

      if (value.length > 32) value = value.slice(0, 32);

      return `<${this.constructor.name}: ${this.bits}:${value.toString(
        'hex',
      )}>`;
    }
  }

  /**
   * OctString
   */

  export class OctString extends Node {
    value: Buffer;

    constructor(value?: Buffer, ...options: any[]) {
      super();
      this.value = EMPTY;
      this.from(value, ...options);
    }

    get type() {
      return types.OCTSTRING;
    }

    getBodySize() {
      return this.value.length;
    }

    writeBody(bw: bio.StaticWriter) {
      bw.writeBytes(this.value);
      return bw;
    }

    readBody(br: bio.BufferReader) {
      this.value = br.readBytes(br.left());
      return this;
    }

    set(value?: Buffer) {
      if (value == null) value = EMPTY;

      assert(Buffer.isBuffer(value));

      this.value = value;

      return this;
    }

    clean() {
      return this.value.length === 0;
    }

    format() {
      let value = this.value;

      if (value.length > 32) value = value.slice(0, 32);

      return `<${this.constructor.name}: ${value.toString('hex')}>`;
    }
  }

  /**
   * Null
   */

  export class Null extends Node {
    constructor(...options: any[]) {
      super();
      this.from(...options);
    }

    get type() {
      return types.NULL;
    }

    getBodySize() {
      return 0;
    }

    writeBody(bw: bio.StaticWriter) {
      return bw;
    }

    readBody(br: bio.BufferReader) {
      if (br.left() !== 0) throw new Error('Non-minimal NULL.');

      return this;
    }

    clean() {
      return true;
    }

    format() {
      return `<${this.constructor.name}>`;
    }
  }

  /**
   * OID
   */

  export class OID extends Node {
    value: Uint32Array;

    constructor(
      value?: number | number[] | Buffer | Uint32Array | string,
      ...options: any[]
    ) {
      super();
      this.value = EMPTY_OID;
      this.from(value, ...options);
    }

    get type() {
      return types.OID;
    }

    getBodySize() {
      const oid = this.value;

      if (oid.length < 2 || oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40))
        throw new Error('Invalid OID.');

      let size = sizeBase128(oid[0] * 40 + oid[1]);

      for (let i = 2; i < oid.length; i++) size += sizeBase128(oid[i]);

      return size;
    }

    writeBody(bw: bio.StaticWriter) {
      const oid = this.value;
      const data = bw.data;

      if (oid.length < 2 || oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40))
        throw new Error('Invalid OID.');

      let off = bw.offset;

      off = writeBase128(data, oid[0] * 40 + oid[1], off);

      for (let i = 2; i < oid.length; i++)
        off = writeBase128(data, oid[i], off);

      bw.offset = off;

      return bw;
    }

    readBody(br: bio.BufferReader) {
      const data = br.readBytes(br.left(), true);

      if (data.length === 0) throw new Error('Zero length OID.');

      const s = new Uint32Array(data.length + 1);

      let [v, off] = readBase128(data, 0);

      if (v < 80) {
        s[0] = (v / 40) >>> 0;
        s[1] = v % 40;
      } else {
        s[0] = 2;
        s[1] = v - 80;
      }

      let i = 2;

      for (; off < data.length; i++) {
        [v, off] = readBase128(data, off);
        s[i] = v;
      }

      this.value = s.subarray(0, i);

      return this;
    }

    equals(oid: OID) {
      assert(oid instanceof OID);
      return isEqual(this.value, oid.value);
    }

    set(value?: number | number[] | Buffer | Uint32Array | string) {
      if (value == null) value = EMPTY_OID;

      if (typeof value === 'string') return this.fromString(value);

      if (Array.isArray(value)) return this.fromArray(value);

      assert(value instanceof Uint32Array);

      this.value = value;

      return this;
    }

    clean() {
      return isEqual(this.value, EMPTY_OID);
    }

    toArray() {
      const arr = [];

      for (const item of this.value) arr.push(item);

      return arr;
    }

    fromArray(arr: number[]) {
      assert(Array.isArray(arr));

      const out = new Uint32Array(arr.length);

      for (let i = 0; i < arr.length; i++) {
        const val = arr[i];
        assert(val >>> 0 === val);
        out[i] = val;
      }

      this.value = out;

      return this;
    }

    toString() {
      let str = '';

      for (let i = 0; i < this.value.length; i++) {
        if (i > 0) str += '.';

        str += this.value[i].toString(10);
      }

      return str;
    }

    fromString(str: string) {
      assert(typeof str === 'string');

      str =
        oids.attrs[str] ??
        oids.keyAlgs[str] ??
        oids.hashes[str] ??
        oids.curves[str] ??
        str;

      const parts = str.split('.');
      const out = new Uint32Array(parts.length);

      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        out[i] = parseU32(part);
      }

      this.value = out;

      return this;
    }

    getAttributeName() {
      return oids.attrsByVal[this.toString()];
    }

    getSignatureAlgorithmName() {
      return oids.sigAlgsByVal[this.toString()];
    }

    getSignatureHash() {
      return oids.sigToHash[this.toString()];
    }

    getSignatureHashName() {
      const oid = this.getSignatureHash();

      if (!oid) return null;

      return oids.hashesByVal[oid];
    }

    getKeyAlgorithmName() {
      return oids.keyAlgsByVal[this.toString()];
    }

    getHashName() {
      return oids.hashesByVal[this.toString()];
    }

    getCurveName() {
      return oids.curvesByVal[this.toString()];
    }

    format() {
      const oid = this.toString();
      const name =
        oids.attrsByVal[oid] ||
        oids.sigAlgsByVal[oid] ||
        oids.keyAlgsByVal[oid] ||
        oids.hashesByVal[oid] ||
        oids.curvesByVal[oid] ||
        'UNKNOWN';

      const str = `${oid} (${name})`;

      return `<${this.constructor.name}: ${str}>`;
    }
  }

  /**
   * Enum
   */

  export class Enum extends Integer {
    constructor(value?: number | Buffer, ...options: any[]) {
      super(value, ...options);
    }

    get type() {
      return types.ENUM;
    }
  }

  /**
   * Utf8String
   */

  export class Utf8String extends Str {
    constructor(...options: any[]) {
      super(...options);
    }

    get type() {
      return types.UTF8STRING;
    }

    get encoding(): BufferEncoding {
      return 'utf8';
    }
  }

  /**
   * RawSequence
   */

  export class RawSequence extends Node {
    value: Buffer;

    constructor(...options: any[]) {
      super();
      this.value = EMPTY;
      this.from(...options);
    }

    get type() {
      return types.SEQUENCE;
    }

    getBodySize() {
      return this.value.length;
    }

    writeBody(bw: bio.StaticWriter) {
      bw.writeBytes(this.value);
      return bw;
    }

    readBody(br: bio.BufferReader) {
      this.value = br.readBytes(br.left());
      return this;
    }

    set(value?: Node[] | Buffer | null) {
      if (value == null) value = EMPTY;

      if (Array.isArray(value)) return this.fromArray(value);

      assert(Buffer.isBuffer(value));

      this.value = value;

      return this;
    }

    clean() {
      return this.value.length === 0;
    }

    *children() {
      const br = bio.read(this.value);

      while (br.left()) yield Any.read<Any>(br).node;
    }

    toArray() {
      const out = [];

      for (const el of this.children()) out.push(el);

      return out;
    }

    fromArray(value: Node[]) {
      assert(Array.isArray(value));

      let size = 0;

      for (const el of value) {
        assert(el instanceof Node);
        size += el.getSize();
      }

      const bw = bio.write(size);

      for (const el of value) el.write(bw);

      this.value = bw.render();

      return this;
    }

    format() {
      return this.toArray();
    }
  }

  /**
   * RawSet
   */

  export class RawSet extends RawSequence {
    constructor(...options: any[]) {
      super(...options);
    }

    get type() {
      return types.SET;
    }
  }

  /**
   * NumString
   */

  export class NumString extends Str {
    constructor(...options: any[]) {
      super(...options);
    }

    get type() {
      return types.NUMSTRING;
    }
  }

  /**
   * PrintString
   */

  export class PrintString extends Str {
    constructor(...options: any[]) {
      super(...options);
    }

    get type() {
      return types.PRINTSTRING;
    }
  }

  /**
   * T61String
   */

  export class T61String extends Str {
    constructor(...options: any[]) {
      super(...options);
    }

    get type() {
      return types.T61STRING;
    }
  }

  /**
   * IA5String
   */

  export class IA5String extends Str {
    constructor(...options: any[]) {
      super(...options);
    }

    get type() {
      return types.IA5STRING;
    }
  }

  /**
   * Time
   */

  export class Time extends Node {
    value: number;
    offset: number;

    constructor(...options: any[]) {
      super();
      this.value = 0;
      this.offset = 0;
      this.from(...options);
    }

    set(value?: number | Buffer | null, offset?: number | null) {
      if (value == null) value = 0;

      if (offset == null) offset = 0;

      if (typeof value === 'string') return this.fromString(value);

      assert(isTime(value));
      assert(isOffset(offset));

      this.value = value;
      this.offset = offset;

      return this;
    }

    clean() {
      return this.value === 0 && this.offset === 0;
    }

    unix() {
      return this.value - this.offset;
    }

    toString() {
      const date = new Date(this.value * 1000);
      const str = date.toISOString().slice(0, -5);
      return str + serializeOffset(this.offset);
    }

    fromString(str: string) {
      assert(typeof str === 'string');

      const ms = Date.parse(str);

      if (ms !== ms) throw new Error('Invalid date string.');

      const time = Math.floor(ms / 1000);

      if (!isTime(time)) throw new Error('Invalid time.');

      this.value = time;
      this.offset = 0;

      return this;
    }

    format() {
      const name = this.constructor.name;
      const value = this.value;

      let off = this.offset.toString(10);

      if (this.offset >= 0) off = '+' + off;

      return `<${name}: ${value}${off} (${this.toString()})>`;
    }
  }

  /**
   * UTCTime
   */

  export class UTCTime extends Time {
    constructor(...options: any[]) {
      super(...options);
    }

    get type() {
      return types.UTCTIME;
    }

    getBodySize() {
      return this.offset === 0 ? 13 : 17;
    }

    writeBody(bw: bio.StaticWriter) {
      assert(isTime(this.value));

      const date = new Date(this.value * 1000);

      let str = '';

      str += two(date.getUTCFullYear() % 100);
      str += two(date.getUTCMonth() + 1);
      str += two(date.getUTCDate());
      str += two(date.getUTCHours());
      str += two(date.getUTCMinutes());
      str += two(date.getUTCSeconds());
      str += serializeOffset(this.offset);

      bw.writeString(str, 'binary');

      return bw;
    }

    readBody(br: bio.BufferReader) {
      const size = br.left();

      if (size !== 13 && size !== 17) throw new Error('Invalid UTCTIME.');

      const str = br.readString(size, 'binary');
      const year = parseU32(str.substring(0, 2));
      const mon = parseU32(str.substring(2, 4));
      const day = parseU32(str.substring(4, 6));
      const hour = parseU32(str.substring(6, 8));
      const min = parseU32(str.substring(8, 10));
      const sec = parseU32(str.substring(10, 12));

      this.value = toSeconds(year, mon, day, hour, min, sec, true);
      this.offset = parseOffset(str.substring(12));

      return this;
    }
  }

  /**
   * GenTime
   */

  export class GenTime extends Time {
    constructor(...options: any[]) {
      super(...options);
    }

    get type() {
      return types.GENTIME;
    }

    getBodySize() {
      return this.offset === 0 ? 15 : 19;
    }

    writeBody(bw: bio.StaticWriter) {
      assert(isTime(this.value));

      const date = new Date(this.value * 1000);

      let str = '';
      str += date.getUTCFullYear().toString(10);
      str += two(date.getUTCMonth() + 1);
      str += two(date.getUTCDate());
      str += two(date.getUTCHours());
      str += two(date.getUTCMinutes());
      str += two(date.getUTCSeconds());
      str += serializeOffset(this.offset);

      bw.writeString(str, 'binary');

      return bw;
    }

    readBody(br: bio.BufferReader) {
      const size = br.left();

      if (size !== 15 && size !== 19) throw new Error('Invalid GENTIME.');

      const str = br.readString(size, 'binary');
      const year = parseU32(str.substring(0, 4));
      const mon = parseU32(str.substring(4, 6));
      const day = parseU32(str.substring(6, 8));
      const hour = parseU32(str.substring(8, 10));
      const min = parseU32(str.substring(10, 12));
      const sec = parseU32(str.substring(12, 14));

      this.value = toSeconds(year, mon, day, hour, min, sec, false);
      this.offset = parseOffset(str.substring(14));

      return this;
    }
  }

  /**
   * GenString
   */

  export class GenString extends Str {
    constructor(...options: any[]) {
      super(...options);
    }

    get type() {
      return types.GENSTRING;
    }
  }

  /**
   * API
   */

  export function typeToClass(type: number) {
    assert(type >>> 0 === type);

    switch (type) {
      case types.BOOLEAN:
        return Bool;
      case types.INTEGER:
        return Integer;
      case types.BITSTRING:
        return BitString;
      case types.OCTSTRING:
        return OctString;
      case types.NULL:
        return Null;
      case types.OID:
        return OID;
      case types.ENUM:
        return Enum;
      case types.UTF8STRING:
        return Utf8String;
      case types.SEQUENCE:
        return RawSequence;
      case types.SET:
        return RawSet;
      case types.NUMSTRING:
        return NumString;
      case types.PRINTSTRING:
        return PrintString;
      case types.T61STRING:
        return T61String;
      case types.IA5STRING:
        return IA5String;
      case types.UTCTIME:
        return UTCTime;
      case types.GENTIME:
        return GenTime;
      case types.GENSTRING:
        return GenString;
      default:
        throw new Error(`Unknown type: ${type}.`);
    }
  }

  /*
   * Helpers
   */

  function sizeHeader(size: number) {
    assert(size >>> 0 === size);

    if (size <= 0x7f) return 1 + 1;

    if (size <= 0xff) return 1 + 1 + 1;

    if (size <= 0xffff) return 1 + 1 + 2;

    assert(size <= 0xffffff);

    return 1 + 1 + 3;
  }

  function writeHeader(
    bw: bio.StaticWriter,
    type: number,
    cls: number,
    primitive: boolean,
    size: number,
  ) {
    assert(bw);
    assert(type >>> 0 === type);
    assert(cls >>> 0 === cls);
    assert(typeof primitive === 'boolean');
    assert(size >>> 0 === size);

    if (!primitive) type |= 0x20;

    type |= cls << 6;

    // Short form.
    if (size <= 0x7f) {
      bw.writeU8(type);
      bw.writeU8(size);

      return bw;
    }

    // Long form (1 byte).
    if (size <= 0xff) {
      bw.writeU8(type);
      bw.writeU8(0x80 | 1);
      bw.writeU8(size);

      return bw;
    }

    // Long form (2 bytes).
    if (size <= 0xffff) {
      bw.writeU8(type);
      bw.writeU8(0x80 | 2);
      bw.writeU16BE(size);

      return bw;
    }

    assert(size <= 0xffffff);

    // Long form (3 bytes).
    bw.writeU8(type);
    bw.writeU8(0x80 | 3);
    bw.writeU24BE(size);

    return bw;
  }

  function readHeader(br: BufferReader) {
    const start = br.offset;
    const field = br.readU8();
    const cls = field >>> 6;
    const primitive = (field & 0x20) === 0;

    let type = field & 0x1f;

    if (type === 0x1f) {
      [type, br.offset] = readBase128(br.data, br.offset);

      if (type < 0x1f) throw new Error('Non-minimal type.');
    }

    switch (cls) {
      case classes.UNIVERSAL:
      case classes.CONTEXT:
        break;
      default:
        throw new Error('Unknown class.');
    }

    const size = readSize(br);
    const len = br.offset - start;

    return {
      type,
      cls,
      primitive,
      size,
      len,
    };
  }

  function peekHeader(br: BufferReader, optional?: boolean) {
    const offset = br.offset;

    let hdr = null;
    let err = null;

    try {
      hdr = readHeader(br);
    } catch (e) {
      err = e;
    }

    br.offset = offset;

    if (!optional && !hdr) throw err;

    return hdr;
  }

  function readSize(br: BufferReader) {
    const field = br.readU8();
    const bytes = field & 0x7f;

    // Definite form
    if ((field & 0x80) === 0) {
      // Short form
      return bytes;
    }

    // Indefinite form.
    if (bytes === 0) throw new Error('Indefinite length.');

    let len = 0;

    for (let i = 0; i < bytes; i++) {
      const ch = br.readU8();

      if (len >= 1 << 24) throw new Error('Length too large.');

      len *= 0x100;
      len += ch;

      if (len === 0) throw new Error('Unexpected leading zeroes.');
    }

    if (len < 0x80) throw new Error('Non-minimal length.');

    return len;
  }

  function sizeBase128(n: number) {
    assert(n >>> 0 === n);

    if (n === 0) return 1;

    let len = 0;

    while (n > 0) {
      len += 1;
      n >>>= 7;
    }

    return len;
  }

  function writeBase128(data: Buffer, n: number, off: number) {
    assert(Buffer.isBuffer(data));
    assert(n >>> 0 === n);
    assert(off >>> 0 === off);

    const l = sizeBase128(n);

    for (let i = l - 1; i >= 0; i--) {
      let o = n >>> (i * 7);

      o &= 0x7f;

      if (i !== 0) o |= 0x80;

      if (off >= data.length)
        throw new bio.EncodingError(off, 'Out of bounds write');

      data[off] = o;
      off += 1;
    }

    return off;
  }

  function readBase128(data: Buffer, off: number) {
    assert(Buffer.isBuffer(data));
    assert(off >>> 0 === off);

    let shifted = 0;
    let num = 0;

    for (; off < data.length; shifted++) {
      if (shifted === 5) throw new Error('Base128 integer too large.');

      const b = data[off];

      num *= 128;
      num += b & 0x7f;

      off += 1;

      if ((b & 0x80) === 0) {
        if (num > 0xffffffff) throw new Error('Base128 integer too large.');

        return [num, off];
      }
    }

    throw new Error('Base128 integer too short.');
  }

  function two(num: number) {
    if (num < 10) return '0' + num.toString(10);
    return num.toString(10);
  }

  function isNumString(str: string) {
    assert(typeof str === 'string');

    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);

      if (ch >= 0x30 && ch <= 0x39) continue;

      if (ch === 0x20) continue;

      return false;
    }

    return true;
  }

  function isPrintString(str: string) {
    assert(typeof str === 'string');

    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);

      // 0 - 9
      if (ch >= 0x30 && ch <= 0x39) continue;

      // A - Z
      if (ch >= 0x41 && ch <= 0x5a) continue;

      // a - z
      if (ch >= 0x61 && ch <= 0x7a) continue;

      switch (ch) {
        case 0x20: // ' '
        case 0x26: // & - nonstandard
        case 0x27: // '
        case 0x28: // (
        case 0x29: // )
        case 0x2a: // * - nonstandard
        case 0x2b: // +
        case 0x2c: // ,
        case 0x2d: // -
        case 0x2e: // .
        case 0x2f: // /
        case 0x3a: // :
        case 0x3d: // =
        case 0x3f: // ?
          continue;
      }

      return false;
    }

    return true;
  }

  function isIA5String(str: string) {
    assert(typeof str === 'string');

    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);

      if (ch >= 0x80) return false;
    }

    return true;
  }

  function parseU32(str: string) {
    assert(typeof str === 'string');

    let word = 0;

    if (str.length === 0 || str.length > 10)
      throw new Error('Invalid integer.');

    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i) - 0x30;

      if (ch < 0 || ch > 9) throw new Error('Invalid integer.');

      word *= 10;
      word += ch;

      if (word > 0xffffffff) throw new Error('Invalid integer.');
    }

    return word;
  }

  function isEqual(a: Uint32Array, b: Uint32Array) {
    assert(a instanceof Uint32Array);
    assert(b instanceof Uint32Array);

    if (a.length !== b.length) return false;

    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }

    return true;
  }

  function trimLeft(buf: Buffer) {
    assert(Buffer.isBuffer(buf));

    if (buf.length === 0) return Buffer.from([0x00]);

    if (buf[0] !== 0x00) return buf;

    for (let i = 1; i < buf.length; i++) {
      if (buf[i] !== 0x00) return buf.slice(i);
    }

    return buf.slice(-1);
  }

  function twosComplement(num: Buffer, start: number, end: number) {
    assert(Buffer.isBuffer(num));
    assert(start >>> 0 === start);
    assert(end >>> 0 === end);
    assert(start <= end);

    let carry = 1;

    for (let i = end - 1; i >= start; i--) {
      carry += num[i] ^ 0xff;
      num[i] = carry & 0xff;
      carry >>>= 8;
    }

    return num;
  }

  function isTime(time: any): time is number {
    if (!Number.isSafeInteger(time)) return false;

    // ASN.1 time ranges from;
    //   0000-01-01T00:00:00.000Z
    // to:
    //   9999-12-31T00:59:59.000Z
    if (time < MIN_TIME || time > MAX_TIME) return false;

    return true;
  }

  function toSeconds(
    year: number,
    mon: number,
    day: number,
    hour: number,
    min: number,
    sec: number,
    utc: boolean,
  ) {
    assert(year >>> 0 === year);
    assert(mon >>> 0 === mon);
    assert(day >>> 0 === day);
    assert(hour >>> 0 === hour);
    assert(min >>> 0 === min);
    assert(sec >>> 0 === sec);
    assert(typeof utc === 'boolean');

    if (utc) {
      if (year < 70) year = 2000 + year;
      else year = 1900 + year;
    }

    // Highest valid date:
    //   new Date(8640000000000000)
    if (year > 275760) throw new Error('Invalid year.');

    if (mon < 1 || mon > 12 || day < 1 || day > 32)
      throw new Error('Invalid month or day.');

    if (hour > 23 || min > 59 || sec > 59)
      throw new Error('Invalid hours, minutes, or seconds.');

    const ms = Date.UTC(year, mon - 1, day, hour, min, sec, 0);

    assert(ms === ms);

    const time = ms / 1000;

    assert(isTime(time));

    return time;
  }

  function isOffset(offset: number) {
    if (!Number.isSafeInteger(offset)) return false;

    // UTC timezones range from -12:00 to +14:00.
    if (offset < MIN_OFFSET || offset > MAX_OFFSET) return false;

    return true;
  }

  function serializeOffset(offset: number) {
    assert(isOffset(offset));

    if (offset === 0) return 'Z';

    let str = '';

    if (offset < 0) {
      str += '-';
      offset = -offset;
    } else {
      str += '+';
    }

    const minutes = (offset / 60) >>> 0;
    const hour = (minutes / 60) >>> 0;
    const min = minutes % 60;

    str += two(hour);
    str += two(min);

    return str;
  }

  function parseOffset(str: string) {
    assert(typeof str === 'string');

    if (str.length === 0) throw new Error('Invalid time offset.');

    const zone = str[0];

    switch (zone) {
      case 'Z': {
        if (str.length !== 1) throw new Error('Non-minimal time offset.');

        return 0;
      }
      case '+':
      case '-': {
        if (str.length !== 5) throw new Error('Non-minimal time offset.');

        const hour = parseU32(str.substring(1, 3));
        const min = parseU32(str.substring(3, 5));
        const minutes = hour * 60 + min;

        let offset = minutes * 60;

        if (zone === '-') offset = -offset;

        if (!isOffset(offset)) throw new Error('Not a time zone.');

        return offset;
      }
    }

    throw new Error('Invalid time offset.');
  }
}
