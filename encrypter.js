const crypto = require('crypto');

function encryptWithPrivateKey(privateKey, message) {
  const buff = Buffer.from(message, 'utf8');

  return crypto.privateEncrypt(privateKey, buff);
}

module.exports.encryptWithPrivateKey = encryptWithPrivateKey;
