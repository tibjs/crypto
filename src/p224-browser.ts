import {extend} from './asyms/ecdsa';

const p224 = extend(require('bcrypto/lib/p224-browser'));

export {p224};
