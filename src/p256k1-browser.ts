import {extend} from './asyms/ecdsa';

const p256k1 = extend(require('bcrypto/lib/secp256k1-browser'));

export {p256k1};
