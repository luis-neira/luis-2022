const crypto = require('crypto');
const got = require('got');

const KeyGenerator = require('./createKeyPair');
const Encrypter = require('./encrypter');

let keyPair = {};

const hasher = crypto.createHash('sha256');

if (require.main === module) {
  const Readline = require('readline');

  const readline = Readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  const question1 = () => {
    return new Promise((resolve, reject) => {
      const msg =
        'Would You like to create an asymmetic keypair? (default: Yes) ';

      readline.question(msg, (answer) => {
        const sanitizedString = answer.toLowerCase();

        if (sanitizedString === '') {
          resolve(KeyGenerator.createKeyPair());
          return;
        }

        if (sanitizedString !== 'yes' && sanitizedString !== 'no') {
          return reject(new Error("String must be 'yes' or 'no'."));
        }

        resolve(KeyGenerator.createKeyPair());
      });
    });
  };

  const question2 = () => {
    return new Promise((resolve, reject) => {
      const msg = 'Enter password to submit publicKey. ';

      readline.question(msg, (answer) => {
        const sanitizedString = answer.toLowerCase();

        if (sanitizedString === '') {
          resolve(new Error('You cannot enter an empty string.'));
          return;
        }

        resolve(sanitizedString.trim());
      });
    });
  };

  const question3 = () => {
    return new Promise((resolve, reject) => {
      const msg = 'Type message to send to sever for verification. ';

      readline.question(msg, (answer) => {
        const sanitizedString = answer.trim();

        if (sanitizedString === '') {
          resolve(new Error('You cannot enter an empty string.'));
          return;
        }

        hasher.update(sanitizedString);

        const hashedData = hasher.digest('hex');

        const signedMsg = Encrypter.encryptWithPrivateKey(keyPair.privateKey, hashedData);

        const data = {
          originalMsg: sanitizedString,
          signedMsg
        }

        resolve(data);
      });
    });
  };

  async function run() {
    keyPair = await question1();

    const enteredPassword = await question2();

    try {
      const signUpResponse = await got.post('http://localhost:8080/signUp', {
          headers: {
            password: enteredPassword
          },
          json: {
            publicKey: keyPair.publicKey
          }
        }).json();

      console.log(signUpResponse);

      const dataPackage = await question3();

      const verifyResponse = await got.post('http://localhost:8080/verify', {
        json: dataPackage
      }).json();

      const successResponse = {
        ...verifyResponse,
        data: {
          originalMsg: verifyResponse.data.originalMsg,
          signedMsg: Buffer.from(verifyResponse.data.signedMsg).toString()
        }
      }

      readline.close();
    } catch (error) {
      if (error.response.statusCode === 401) {
        throw new Error('Unauthorized');
      }
      throw error;
    }
  }

  run().catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
