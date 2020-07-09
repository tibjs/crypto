import {extend} from './asyms/ecdsa';

const p384 = extend(require('bcrypto/lib/p384-browser'));

export {p384};
