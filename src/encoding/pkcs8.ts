/*!
 * pkcs8.js - PKCS8 encoding for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/PKCS_8
 *   https://tools.ietf.org/html/rfc5208
 *   https://tools.ietf.org/html/rfc5958
 *   https://github.com/golang/go/blob/master/src/crypto/x509/pkcs8.go
 */

import {BufferReader, StaticWriter} from '@artlab/bufio';
import {asn1} from './asn1';
import {pem} from './pem';
import {x509} from './x509';
import {UnsignedValue} from './types';

export namespace pkcs8 {
  /**
   * PublicKeyInfo
   */

  // PublicKeyInfo ::= SEQUENCE {
  //   algorithm       AlgorithmIdentifier,
  //   PublicKey       BIT STRING
  // }

  export class PublicKeyInfo extends asn1.Sequence {
    algorithm: x509.AlgorithmIdentifier;
    publicKey: asn1.BitString;

    constructor(
      algorithm?: string | number | number[] | Buffer | Uint32Array,
      identifier?: asn1.Node,
      publicKey?: number | Buffer,
    ) {
      super();
      this.algorithm = new x509.AlgorithmIdentifier(algorithm, identifier);
      this.publicKey = new asn1.BitString(publicKey);
    }

    getBodySize() {
      let size = 0;
      size += this.algorithm.getSize();
      size += this.publicKey.getSize();
      return size;
    }

    writeBody(bw: StaticWriter) {
      this.algorithm.write(bw);
      this.publicKey.write(bw);
      return bw;
    }

    readBody(br: BufferReader) {
      this.algorithm.read(br);
      this.publicKey.read(br);
      return this;
    }

    clean() {
      return this.algorithm.clean() && this.publicKey.clean();
    }

    toPEM() {
      return pem.toPEM(this.encode(), 'PUBLIC KEY');
    }

    fromPEM(str: string) {
      const data = pem.fromPEM(str, 'PUBLIC KEY');
      return this.decode(data);
    }

    format() {
      return {
        type: this.constructor.name,
        algorithm: this.algorithm,
        publicKey: this.publicKey,
      };
    }
  }

  /**
   * PrivateKeyInfo
   */

  // PrivateKeyInfo ::= SEQUENCE {
  //   version         Version,
  //   algorithm       AlgorithmIdentifier,
  //   PrivateKey      OCTET STRING
  // }
  //
  // PrivateKeyInfo ::= SEQUENCE {
  //    version Version,
  //    privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
  //    privateKey PrivateKey,
  //    attributes [0] Attributes OPTIONAL
  // }
  //
  // Version ::= INTEGER {v1(0)} (v1,...)
  //
  // PrivateKey ::= OCTET STRING

  export class PrivateKeyInfo extends asn1.Sequence {
    version: asn1.Unsigned;
    privateKey: asn1.OctString;
    algorithm: x509.AlgorithmIdentifier;

    constructor(
      version?: UnsignedValue,
      algorithm?: string | number | Buffer | number[] | Uint32Array,
      parameters?: asn1.Node,
      privateKey?: Buffer,
    ) {
      super();
      this.version = new asn1.Unsigned(version);
      this.algorithm = new x509.AlgorithmIdentifier(algorithm, parameters);
      this.privateKey = new asn1.OctString(privateKey);
    }

    get isRaw() {
      return true;
    }

    getBodySize() {
      let size = 0;
      size += this.version.getSize();
      size += this.algorithm.getSize();
      size += this.privateKey.getSize();
      return size;
    }

    writeBody(bw: StaticWriter) {
      this.version.write(bw);
      this.algorithm.write(bw);
      this.privateKey.write(bw);
      return bw;
    }

    readBody(br: BufferReader) {
      this.version.read(br);
      this.algorithm.read(br);
      this.privateKey.read(br);
      return this;
    }

    clean() {
      return (
        this.version.clean() &&
        this.algorithm.clean() &&
        this.privateKey.clean()
      );
    }

    toPEM() {
      return pem.toPEM(this.encode(), 'PRIVATE KEY');
    }

    fromPEM(str: string) {
      const data = pem.fromPEM(str, 'PRIVATE KEY');
      return this.decode(data);
    }

    format() {
      return {
        type: this.constructor.name,
        version: this.version,
        algorithm: this.algorithm,
        privateKey: this.privateKey,
      };
    }
  }

  /**
   * EncryptedPrivateKeyInfo
   */

  // EncryptedPrivateKeyInfo ::= SEQUENCE {
  //   encryptionAlgorithm  EncryptionAlgorithmIdentifier,
  //   encryptedData        EncryptedData
  // }
  //
  // EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
  //
  // EncryptedData ::= OCTET STRING

  export class EncryptedPrivateKeyInfo extends asn1.Sequence {
    algorithm: x509.AlgorithmIdentifier;
    data: asn1.OctString;

    constructor(
      algorithm?: string | number | number[] | Buffer | Uint32Array,
      identifier?: asn1.Node,
      data?: Buffer,
    ) {
      super();
      this.algorithm = new x509.AlgorithmIdentifier(algorithm, identifier);
      this.data = new asn1.OctString(data);
    }

    getBodySize() {
      let size = 0;
      size += this.algorithm.getSize();
      size += this.data.getSize();
      return size;
    }

    writeBody(bw: StaticWriter) {
      this.algorithm.write(bw);
      this.data.write(bw);
      return bw;
    }

    readBody(br: BufferReader) {
      this.algorithm.read(br);
      this.data.read(br);
      return this;
    }

    clean() {
      return this.algorithm.clean() && this.data.clean();
    }

    toPEM() {
      return pem.toPEM(this.encode(), 'ENCRYPTED PRIVATE KEY');
    }

    fromPEM(str: string) {
      const data = pem.fromPEM(str, 'ENCRYPTED PRIVATE KEY');
      return this.decode(data);
    }

    format() {
      return {
        type: this.constructor.name,
        algorithm: this.algorithm,
        data: this.data,
      };
    }
  }
}
