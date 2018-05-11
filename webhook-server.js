const express = require('express');
const app = express();
const helmet = require('helmet');
const bodyParser = require('body-parser');
const crypto = require('crypto');

// WW
const appId = process.env.APPID;
const appSecret = process.env.APPSECRET;
const webhookSecret = process.env.WEBHOOKSECRET;

if (!webhookSecret) {
  console.log('you shall not pass! webhook secret missing!\n\n');
  process.exit(1);
}

function validate(req, res, next) {
  // console.log(req.body);

  if (req.body.type && req.body.type === 'verification') {
    console.log('verifying challenge');
    const bodyToSend = {
      response: req.body
    };

    const hashToSend = crypto.createHmac('sha256', webhookSecret)
      .update(JSON.stringify(bodyToSend))
      .digest('hex');

    res.set('X-OUTBOUND-TOKEN', hashToSend);
    res.send(bodyToSend).end();
  } else {
    console.log('must be a message');
    next();
  }
}

// set-up middleware
app.use(helmet());
app.use(bodyParser.json());
app.use(validate);

app.get('/', (req, res) => res.send('running'));

app.post('/webhook', (req, res) => {
  res.send(req.body);
});

app.listen(3000, () => console.log('listening on port 3000'));

