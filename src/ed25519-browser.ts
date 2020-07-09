import {extend} from './asyms/eddsa';

const ed25519 = extend(require('bcrypto/lib/ed25519-browser'));

export {ed25519};
