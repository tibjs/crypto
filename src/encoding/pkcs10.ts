import {asn1} from './asn1';
import {pem} from './pem';
import {x509} from './x509';
import {BufferReader, StaticWriter} from '@artlab/bufio';

export namespace pkcs10 {
  /**
   * CertificationRequest ::= SEQUENCE {
   *    certificationRequestInfo CertificationRequestInfo,
   *    signatureAlgorithm       AlgorithmIdentifier{{ SignatureAlgorithms }},
   *    signature                BIT STRING
   * }
   */
  export class CertificationRequest extends asn1.Sequence {
    certificationRequestInfo: CertificationRequestInfo;
    signatureAlgorithm: x509.AlgorithmIdentifier;
    signature: asn1.BitString;

    constructor() {
      super();
      this.certificationRequestInfo = new CertificationRequestInfo();
      this.signatureAlgorithm = new x509.AlgorithmIdentifier();
      this.signature = new asn1.BitString();
    }

    get isRaw() {
      return true;
    }

    getBodySize() {
      let size = 0;
      size += this.certificationRequestInfo.getSize();
      size += this.signatureAlgorithm.getSize();
      size += this.signature.getSize();
      return size;
    }

    writeBody(bw: StaticWriter) {
      this.certificationRequestInfo.write(bw);
      this.signatureAlgorithm.write(bw);
      this.signature.write(bw);
      return bw;
    }

    readBody(br: BufferReader) {
      this.certificationRequestInfo.read(br);
      this.signatureAlgorithm.read(br);
      this.signature.read(br);
      return this;
    }

    clean() {
      return (
        this.certificationRequestInfo.clean() &&
        this.signatureAlgorithm.clean() &&
        this.signature.clean()
      );
    }

    toPEM() {
      return pem.toPEM(this.encode(), 'CERTIFICATE REQUEST');
    }

    fromPEM(str: string) {
      const data = pem.fromPEM(str, 'CERTIFICATE REQUEST');
      return this.decode(data);
    }

    format() {
      return {
        type: this.constructor.name,
        certificationRequestInfo: this.certificationRequestInfo,
        signatureAlgorithm: this.signatureAlgorithm,
        signature: this.signature,
      };
    }
  }

  /**
   * CertificationRequestInfo ::= SEQUENCE {
   *   version       INTEGER { v1(0) } (v1,...),
   *   subject       Name,
   *   subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
   *   attributes    [0] Attributes{{ CRIAttributes }}
   * }
   */
  export class CertificationRequestInfo extends asn1.Sequence {
    version: asn1.Integer;
    subject: x509.RDNSequence;
    subjectPublicKeyInfo: x509.SubjectPublicKeyInfo;
    attributes: Attributes;

    constructor() {
      super();
      this.version = new asn1.Integer();
      this.subject = new x509.RDNSequence();
      this.subjectPublicKeyInfo = new x509.SubjectPublicKeyInfo();
      this.attributes = new Attributes().optional(true);
    }

    get isRaw() {
      return true;
    }

    getBodySize() {
      let size = 0;
      size += this.version.getSize();
      size += this.subject.getSize();
      size += this.subjectPublicKeyInfo.getSize();
      size += this.attributes.getSize();
      return size;
    }

    writeBody(bw: StaticWriter) {
      this.version.write(bw);
      this.subject.write(bw);
      this.subjectPublicKeyInfo.write(bw);
      this.attributes.write(bw);
      return bw;
    }

    readBody(br: BufferReader) {
      this.version.read(br);
      this.subject.read(br);
      this.subjectPublicKeyInfo.read(br);
      this.attributes.read(br);
      return this;
    }

    clean() {
      return (
        this.version.clean() &&
        this.subject.clean() &&
        this.subjectPublicKeyInfo.clean() &&
        this.attributes.clean()
      );
    }

    toPEM() {
      return pem.toPEM(this.encode(), 'CERTIFICATE REQUEST INFO');
    }

    fromPEM(str: string) {
      const data = pem.fromPEM(str, 'CERTIFICATE REQUEST INFO');
      return this.decode(data);
    }

    format() {
      return {
        type: this.constructor.name,
        version: this.version,
        subject: this.subject,
        subjectPublicKeyInfo: this.subjectPublicKeyInfo,
        attributes: this.attributes,
      };
    }
  }

  export class Attributes extends asn1.Sequence {
    // attributes: Attribute[];

    constructor() {
      super();
      // this.attributes = [];
    }

    getBodySize() {
      const size = 0;

      // for (const ext of this.attributes) {
      //   size += ext.getSize();
      // }

      return size;
    }

    writeBody(bw: StaticWriter) {
      // for (const ext of this.attributes) {
      //   ext.write(bw);
      // }

      return bw;
    }

    readBody(br: BufferReader) {
      // while (br.left()) {
      //   const ext: Attribute = Attribute.read(br);
      //   this.attributes.push(ext);
      // }

      return this;
    }

    clean() {
      return true;
      // && this.attributes.length === 0;
    }

    format() {
      return {
        type: this.constructor.name,
        // attributes: this.attributes,
      };
    }
  }
}
