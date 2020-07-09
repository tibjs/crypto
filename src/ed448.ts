import {extend} from './asyms/eddsa';

const ed448 = extend(require('bcrypto/lib/ed448'));

export {ed448};
