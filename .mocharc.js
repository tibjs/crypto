const {mergeMochaConfigs} = require('@tib/build');
const defaultConfig = require('@tib/build/config/.mocharc.json');

const CRYPTO_CONFIG = {
  timeout: 10000,
};

module.exports = mergeMochaConfigs(defaultConfig, CRYPTO_CONFIG);
