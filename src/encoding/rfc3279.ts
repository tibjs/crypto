/*!
 * rfc3279.js - rfc3279 encoding for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc3279
 *   https://tools.ietf.org/html/rfc5912
 */

import {StaticWriter, BufferReader} from '@tib/bufio';
import {asn1} from './asn1';
import {pem} from './pem';

export namespace rfc3279 {
  /**
   * DSA Parms
   */

  // Dss-Parms  ::=  SEQUENCE  {
  //     p             INTEGER,
  //     q             INTEGER,
  //     g             INTEGER  }

  export class DSAParams extends asn1.Sequence {
    p: asn1.Unsigned;
    q: asn1.Unsigned;
    g: asn1.Unsigned;

    constructor(p: number, q: number, g: number) {
      super();
      this.p = new asn1.Unsigned(p);
      this.q = new asn1.Unsigned(q);
      this.g = new asn1.Unsigned(g);
    }

    getBodySize() {
      let size = 0;
      size += this.p.getSize();
      size += this.q.getSize();
      size += this.g.getSize();
      return size;
    }

    writeBody(bw: StaticWriter) {
      this.p.write(bw);
      this.q.write(bw);
      this.g.write(bw);
      return bw;
    }

    readBody(br: BufferReader) {
      this.p.read(br);
      this.q.read(br);
      this.g.read(br);
      return this;
    }

    clean() {
      return this.p.clean() && this.q.clean() && this.g.clean();
    }

    toPEM() {
      return pem.toPEM(this.encode(), 'DSA PARAMETERS');
    }

    fromPEM(str: string) {
      const data = pem.fromPEM(str, 'DSA PARAMETERS');
      return this.decode(data);
    }

    format() {
      return {
        type: this.constructor.name,
        p: this.p,
        q: this.q,
        g: this.g,
      };
    }
  }

  /**
   * DSA Public Key
   */

  // DSAPublicKey ::= INTEGER -- public key, Y

  export class DSAPublicKey extends asn1.Unsigned {
    constructor(y: number) {
      super(y);
    }

    get y() {
      return this.value;
    }

    set y(value) {
      this.value = value;
    }

    toPEM() {
      return pem.toPEM(this.encode(), 'DSA PUBLIC KEY');
    }

    fromPEM(str: string) {
      const data = pem.fromPEM(str, 'DSA PUBLIC KEY');
      return this.decode(data);
    }
  }

  /**
   * DSA Signature
   */

  export class DSASignature extends asn1.Sequence {
    r: asn1.Unsigned;
    s: asn1.Unsigned;

    constructor(r: number, s: number) {
      super();
      this.r = new asn1.Unsigned(r);
      this.s = new asn1.Unsigned(s);
    }

    getBodySize() {
      let size = 0;
      size += this.r.getSize();
      size += this.s.getSize();
      return size;
    }

    writeBody(bw: StaticWriter) {
      this.r.write(bw);
      this.s.write(bw);
      return bw;
    }

    readBody(br: BufferReader) {
      this.r.read(br);
      this.s.read(br);
      return this;
    }

    clean() {
      return this.r.clean() && this.s.clean();
    }

    toPEM() {
      return pem.toPEM(this.encode(), 'DSA SIGNATURE');
    }

    fromPEM(str: string) {
      const data = pem.fromPEM(str, 'DSA SIGNATURE');
      return this.decode(data);
    }

    format() {
      return {
        type: this.constructor.name,
        r: this.r,
        s: this.s,
      };
    }
  }
}
