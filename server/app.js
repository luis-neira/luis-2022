const express = require('express');
const bcrypt = require('bcrypt');
const createError = require('http-errors');
const crypto = require('crypto');

const Decrypter = require('../decrypter');

const app = express();

const USER_PASSWORD = process.env.PASSWORD || '123xyz';

const hash = bcrypt.hashSync(USER_PASSWORD, 10);

const db = {
  hashedPasword: hash,
  publicKey: ''
};

// middleware
app.use(express.json());

app.post('/verify', function (req, res, next) {
  
  const dataPackage = req.body;

  const decryptMsg = Decrypter.decryptWithPublicKey(
    db.publicKey,
    Buffer.from(dataPackage.signedMsg)
  );

  const decryptMsgHex = decryptMsg.toString();
  const hasher = crypto.createHash('sha256');

  hasher.update(dataPackage.originalMsg);

  const hashOfOriginalHex = hasher.digest('hex');

  if (hashOfOriginalHex === decryptMsgHex) {
    res.json({
      success: true,
      data: dataPackage
    });
  } else {
    return next(createError(400));
  }
});

app.post('/signUp', async (req, res, next) => {
  const password = req.headers['password'];

  try {
    // simple validation
    if (!password) {
      throw createError(401);
    }

    // validate password
    const isMatch = await bcrypt.compare(password, db.hashedPasword);

    // password is not valid
    if (!isMatch) {
      throw createError(401);
    }

    if (!req.body.publicKey) {
      throw createError(400);
    }

    db.publicKey = req.body.publicKey;

    console.log(db);

    res.send({ success: true });
  } catch (error) {
    next(error);
  }
});

// 404 handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  console.log(err)
  res.status(err.status || 500).json({
    error: err.message
  });
});

module.exports = app;
