import {Adsa, Asym, HashCtor} from '../../types';
import {ed25519} from '../../ed25519';
import {ed448} from '../../ed448';
import {p192} from '../../p192';
import {p224} from '../../p224';
import {p256} from '../../p256';
import {p384} from '../../p384';
import {p521} from '../../p521';
import {secp256k1} from '../../secp256k1';
import {rsa} from '../../rsa';
import {SHA384} from '../../sha384';
import {SHA256} from '../../sha256';
import {SHA512} from '../../sha512';
import {SHA1} from '../../sha1';
import {SHA3} from '../../sha3';
import {SHA3_224} from '../../sha3-224';
import {SHA3_256} from '../../sha3-256';
import {SHA3_384} from '../../sha3-384';
import {SHA3_512} from '../../sha3-512';
import {BLAKE2b256} from '../../blake2b256';
import {BLAKE2s256} from '../../blake2s256';
import {random} from '../../random';
import {expect} from '@artlab/testlab';

const adsables: Asym<any, any>[] = [
  ed448,
  ed25519,
  p192,
  p224,
  p256,
  p384,
  p521,
  secp256k1,
  rsa,
];

const hashes: HashCtor[] = [
  SHA384,
  SHA256,
  SHA512,
  SHA1,
  SHA3,
  SHA3_224,
  SHA3_256,
  SHA3_384,
  SHA3_512,
  BLAKE2b256,
  BLAKE2s256,
];

const adsas: Adsa[] = [];
for (const adsable of adsables) {
  for (const hash of hashes) {
    adsas.push(adsable.adsa(hash));
  }
}

describe('ADSA', function () {
  for (const adsa of adsas) {
    it(`should generate keypair and sign RS (${adsa.id})`, function () {
      const msg = random.randomBytes(128);

      const priv = adsa.asym.privateKeyGenerate();
      const pub = adsa.asym.publicKeyCreate(priv);
      // compress is not work for RSA.
      // with RSA, pub and pubu is the same
      const pubu = adsa.asym.publicKeyCreate(priv, false);

      const sig = adsa.sign(msg, priv);

      expect(adsa.verify(msg, sig, pub)).ok();
      expect(adsa.verify(msg, sig, pubu)).ok();

      sig[0] ^= 1;

      expect(!adsa.verify(msg, sig, pub)).ok();
      expect(!adsa.verify(msg, sig, pubu)).ok();

      sig[0] ^= 1;

      expect(adsa.verify(msg, sig, pub)).ok();
      expect(adsa.verify(msg, sig, pubu)).ok();
    });
  }
});
