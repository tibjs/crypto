import {CipherExports} from './types/cipher';

let cipher: CipherExports;

if (process.env.NODE_BACKEND === 'js') {
  cipher = require('./js/cipher');
} else {
  cipher = require('./native/cipher');
}

export {cipher};
