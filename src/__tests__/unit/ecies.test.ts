import {assert} from '@tib/bsert';
import path from 'path';
import fs from 'fs';
import {p192} from '../../p192';
import {p224} from '../../p224';
import {p256} from '../../p256';
import {p384} from '../../p384';
import {p521} from '../../p521';
import {secp256k1} from '../../secp256k1';
import {ed25519} from '../../ed25519';
import {ed448} from '../../ed448';
import {x25519} from '../../x25519';
import {x448} from '../../x448';
import {RNG} from '../util/rng';
import {SHA256} from '../../sha256';
import {ecies} from '../../ecies';

const PATH = path.join(__dirname, '..', 'data', 'ies');

const curves = [
  p192,
  p224,
  p256,
  p384,
  p521,
  secp256k1,
  ed25519,
  ed448,
  x25519,
  x448,
];

describe('ECIES', function () {
  const rng = new RNG();

  for (const curve of curves) {
    it(`should encrypt and decrypt (${curve.id})`, () => {
      const alicePriv = rng.privateKeyGenerate(curve);
      const bobPriv = rng.privateKeyGenerate(curve);
      const bobPub = curve.publicKeyCreate(bobPriv);

      const msg = rng.randomBytes(rng.randomRange(0, 100));
      const ct = ecies.encrypt(curve, SHA256, msg, bobPub, alicePriv);

      assert.notBufferEqual(ct, msg);
      assert(ct.length > msg.length);

      const pt = ecies.decrypt(curve, SHA256, ct, bobPriv);
      assert.bufferEqual(pt, msg);

      assert.throws(() => {
        ecies.decrypt(curve, SHA256, ct, alicePriv);
      });

      ct[1] ^= 1;
      assert.throws(() => {
        ecies.decrypt(curve, SHA256, ct, bobPriv);
      });
      ct[1] ^= 1;
    });
  }

  for (const curve of curves) {
    const file = path.join(PATH, `${curve.id.toLowerCase()}.json`);
    const text = fs.readFileSync(file, 'utf8');
    const vectors: string[][] = JSON.parse(text);

    for (const [i, json] of vectors.entries()) {
      const vector = json.map(item => Buffer.from(item, 'hex'));
      const [, bob, , msg, ct] = vector;

      it(`should decrypt ciphertext #${i + 1} (${curve.id})`, () => {
        const pt = ecies.decrypt(curve, SHA256, ct, bob);
        assert.bufferEqual(pt, msg);
      });
    }
  }
});
