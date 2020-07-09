import {extend} from './asyms/ecdsa';

const p384 = extend(require('bcrypto/lib/p384'));

export {p384};
