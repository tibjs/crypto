/*!
 * pkcs3.js - PKCS3 encoding for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://www.teletrust.de/fileadmin/files/oid/oid_pkcs-3v1-4.pdf
 */

import {asn1} from './asn1';
import {pem} from './pem';
import {StaticWriter, BufferReader} from '@artlab/bufio';

export namespace pkcs3 {
  /**
   * DHParams
   */

  export class DHParams extends asn1.Sequence {
    p: asn1.Unsigned;
    g: asn1.Unsigned;

    constructor(p: number, g: number) {
      super();
      this.p = new asn1.Unsigned(p);
      this.g = new asn1.Unsigned(g);
    }

    getBodySize() {
      let size = 0;
      size += this.p.getSize();
      size += this.g.getSize();
      return size;
    }

    writeBody(bw: StaticWriter) {
      this.p.write(bw);
      this.g.write(bw);
      return bw;
    }

    readBody(br: BufferReader) {
      this.p.read(br);
      this.g.read(br);
      return this;
    }

    clean() {
      return this.p.clean() && this.g.clean();
    }

    toPEM() {
      return pem.toPEM(this.encode(), 'DH PARAMETERS');
    }

    fromPEM(str: string) {
      const data = pem.fromPEM(str, 'DH PARAMETERS');
      return this.decode(data);
    }

    format() {
      return {
        type: this.constructor.name,
        p: this.p,
        g: this.g,
      };
    }
  }
}
