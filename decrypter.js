const crypto = require('crypto');

function decryptWithPublicKey(publicKey, encryptedMsg) {
  return crypto.publicDecrypt(publicKey, encryptedMsg);
}

module.exports.decryptWithPublicKey = decryptWithPublicKey;
