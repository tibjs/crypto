/*!
 * pkcs1.js - PKCS1 encoding for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/PKCS_1
 *   https://tools.ietf.org/html/rfc3447
 *   https://tools.ietf.org/html/rfc8017#appendix-A.1.1
 *   https://tools.ietf.org/html/rfc8017#appendix-A.1.2
 *   https://github.com/golang/go/blob/master/src/crypto/x509/pkcs1.go
 *   https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_asn1.c
 */

import {BufferReader, StaticWriter} from '@tib/bufio';
import {asn1} from './asn1';
import {pem} from './pem';
import {UnsignedValue} from './types';

export namespace pkcs1 {
  /**
   * RSAPublicKey
   */

  // RSAPublicKey ::= SEQUENCE {
  //     modulus           INTEGER,  -- n
  //     publicExponent    INTEGER   -- e
  // }

  export class RSAPublicKey extends asn1.Sequence {
    n: asn1.Unsigned;
    e: asn1.Unsigned;

    constructor(n: UnsignedValue, e: UnsignedValue) {
      super();
      this.n = new asn1.Unsigned(n);
      this.e = new asn1.Unsigned(e);
    }

    getBodySize() {
      let size = 0;
      size += this.n.getSize();
      size += this.e.getSize();
      return size;
    }

    writeBody(bw: StaticWriter) {
      this.n.write(bw);
      this.e.write(bw);
      return bw;
    }

    readBody(br: BufferReader) {
      this.n.read(br);
      this.e.read(br);
      return this;
    }

    clean() {
      return this.n.clean() && this.e.clean();
    }

    toPEM() {
      return pem.toPEM(this.encode(), 'RSA PUBLIC KEY');
    }

    fromPEM(str: string) {
      const data = pem.fromPEM(str, 'RSA PUBLIC KEY');
      return this.decode(data);
    }

    format() {
      return {
        type: this.constructor.name,
        n: this.n,
        e: this.e,
      };
    }
  }

  /**
   * RSAPrivateKey
   */

  // RSAPrivateKey ::= SEQUENCE {
  //   version           Version,
  //   modulus           INTEGER,  -- n
  //   publicExponent    INTEGER,  -- e
  //   privateExponent   INTEGER,  -- d
  //   prime1            INTEGER,  -- p
  //   prime2            INTEGER,  -- q
  //   exponent1         INTEGER,  -- d mod (p-1)
  //   exponent2         INTEGER,  -- d mod (q-1)
  //   coefficient       INTEGER,  -- (inverse of q) mod p
  //   otherPrimeInfos   OtherPrimeInfos OPTIONAL
  // }

  export class RSAPrivateKey extends asn1.Sequence {
    version: asn1.Unsigned;
    n: asn1.Unsigned;
    e: asn1.Unsigned;
    d: asn1.Unsigned;
    p: asn1.Unsigned;
    q: asn1.Unsigned;
    dp: asn1.Unsigned;
    dq: asn1.Unsigned;
    qi: asn1.Unsigned;

    constructor(
      version: UnsignedValue,
      n: UnsignedValue,
      e: UnsignedValue,
      d: UnsignedValue,
      p: UnsignedValue,
      q: UnsignedValue,
      dp: UnsignedValue,
      dq: UnsignedValue,
      qi: UnsignedValue,
    ) {
      super();
      this.version = new asn1.Unsigned(version);
      this.n = new asn1.Unsigned(n);
      this.e = new asn1.Unsigned(e);
      this.d = new asn1.Unsigned(d);
      this.p = new asn1.Unsigned(p);
      this.q = new asn1.Unsigned(q);
      this.dp = new asn1.Unsigned(dp);
      this.dq = new asn1.Unsigned(dq);
      this.qi = new asn1.Unsigned(qi);
    }

    getBodySize() {
      let size = 0;
      size += this.version.getSize();
      size += this.n.getSize();
      size += this.e.getSize();
      size += this.d.getSize();
      size += this.p.getSize();
      size += this.q.getSize();
      size += this.dp.getSize();
      size += this.dq.getSize();
      size += this.qi.getSize();
      return size;
    }

    writeBody(bw: StaticWriter) {
      this.version.write(bw);
      this.n.write(bw);
      this.e.write(bw);
      this.d.write(bw);
      this.p.write(bw);
      this.q.write(bw);
      this.dp.write(bw);
      this.dq.write(bw);
      this.qi.write(bw);
      return bw;
    }

    readBody(br: BufferReader) {
      this.version.read(br);
      this.n.read(br);
      this.e.read(br);
      this.d.read(br);
      this.p.read(br);
      this.q.read(br);
      this.dp.read(br);
      this.dq.read(br);
      this.qi.read(br);
      return this;
    }

    clean() {
      return (
        this.n.clean() &&
        this.e.clean() &&
        this.d.clean() &&
        this.p.clean() &&
        this.q.clean() &&
        this.dp.clean() &&
        this.dq.clean() &&
        this.qi.clean()
      );
    }

    toPEM() {
      return pem.toPEM(this.encode(), 'RSA PRIVATE KEY');
    }

    fromPEM(str: string) {
      const data = pem.fromPEM(str, 'RSA PRIVATE KEY');
      return this.decode(data);
    }

    format() {
      return {
        type: this.constructor.name,
        version: this.version,
        n: this.n,
        e: this.e,
        d: this.d,
        p: this.p,
        q: this.q,
        dp: this.dp,
        dq: this.dq,
        qi: this.qi,
      };
    }
  }
}
