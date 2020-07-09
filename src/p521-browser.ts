import {extend} from './asyms/ecdsa';

const p521 = extend(require('bcrypto/lib/p521-browser'));

export {p521};
