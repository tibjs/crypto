import {expect} from '@artlab/testlab';
import {HashCtor} from '../../types';

import {BLAKE2b160} from '../../blake2b160';
import {BLAKE2b256} from '../../blake2b256';
import {BLAKE2b384} from '../../blake2b384';
import {BLAKE2b512} from '../../blake2b512';
import {BLAKE2s128} from '../../blake2s128';
import {BLAKE2s160} from '../../blake2s160';
import {BLAKE2s224} from '../../blake2s224';
import {BLAKE2s256} from '../../blake2s256';
import {GOST94} from '../../gost94';
import {Hash160} from '../../hash160';
import {Hash256} from '../../hash256';
import {Keccak224} from '../../keccak224';
import {Keccak256} from '../../keccak256';
import {Keccak384} from '../../keccak384';
import {Keccak512} from '../../keccak512';
import {MD2} from '../../md2';
import {MD4} from '../../md4';
import {MD5} from '../../md5';
import {MD5SHA1} from '../../md5sha1';
import {RIPEMD160} from '../../ripemd160';
import {SHA1} from '../../sha1';
import {SHA224} from '../../sha224';
import {SHA256} from '../../sha256';
import {SHA384} from '../../sha384';
import {SHA512} from '../../sha512';
import {SHA3_224} from '../../sha3-224';
import {SHA3_256} from '../../sha3-256';
import {SHA3_384} from '../../sha3-384';
import {SHA3_512} from '../../sha3-512';
import {SHAKE128} from '../../shake128';
import {SHAKE256} from '../../shake256';
import {Whirlpool} from '../../whirlpool';

const hashes: [string, HashCtor][] = [
  ['blake2b160', BLAKE2b160],
  ['blake2b256', BLAKE2b256],
  ['blake2b384', BLAKE2b384],
  ['blake2b512', BLAKE2b512],
  ['blake2s128', BLAKE2s128],
  ['blake2s160', BLAKE2s160],
  ['blake2s224', BLAKE2s224],
  ['blake2s256', BLAKE2s256],
  ['gost94', GOST94],
  ['hash160', Hash160],
  ['hash256', Hash256],
  ['keccak224', Keccak224],
  ['keccak256', Keccak256],
  ['keccak384', Keccak384],
  ['keccak512', Keccak512],
  ['md2', MD2],
  ['md4', MD4],
  ['md5', MD5],
  ['md5sha1', MD5SHA1],
  ['ripemd160', RIPEMD160],
  ['sha1', SHA1],
  ['sha224', SHA224],
  ['sha256', SHA256],
  ['sha384', SHA384],
  ['sha512', SHA512],
  ['sha3_224', SHA3_224],
  ['sha3_256', SHA3_256],
  ['sha3_384', SHA3_384],
  ['sha3_512', SHA3_512],
  ['shake128', SHAKE128],
  ['shake256', SHAKE256],
  ['whirlpool', Whirlpool],
];

describe('Hash', function () {
  for (const [name, hash] of hashes) {
    it(`should export correctly for ${name}`, function () {
      expect(hash.id).equal(name.toUpperCase());
    });
  }
});
