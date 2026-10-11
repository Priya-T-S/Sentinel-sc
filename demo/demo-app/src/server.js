// acme-orders-api — SENTINEL-SC demo application.
// Intentionally uses vulnerable dependency versions. DO NOT DEPLOY.
const express = require('express');
const _ = require('lodash');
const axios = require('axios');
const dayjs = require('dayjs');
const ordersRouter = require('./routes/orders');

const app = express();
app.use(express.json());
app.use('/orders', ordersRouter);

// Renders a receipt from a user-supplied template string.
// lodash < 4.17.21 `template` is affected by GHSA-35jh-r3h4-6jhm (command injection).
app.post('/receipt', (req, res) => {
  const compiled = _.template(req.body.layout || 'Order <%= id %> placed <%= when %>');
  res.send(compiled({ id: req.body.id, when: dayjs().format('YYYY-MM-DD') }));
});

app.get('/rates', async (req, res) => {
  const r = await axios.get('https://api.example.com/rates');
  res.json(r.data);
});

app.listen(process.env.PORT || 3000);
