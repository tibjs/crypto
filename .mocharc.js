const {mergeMochaConfigs} = require('@artlab/build');
const defaultConfig = require('@artlab/build/config/.mocharc.json');

const CRYPTO_CONFIG = {
  timeout: 10000,
};

module.exports = mergeMochaConfigs(defaultConfig, CRYPTO_CONFIG);
