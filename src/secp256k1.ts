import {extend} from './asyms/ecdsa';

const secp256k1 = extend(require('bcrypto/lib/secp256k1'));

export {secp256k1};
