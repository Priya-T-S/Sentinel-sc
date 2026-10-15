const express = require('express');
const _ = require('lodash');
const axios = require('axios');
const app = express();
app.get('/health', (req, res) => res.json({ ok: true, at: _.now() }));
app.get('/rates', async (req, res) => res.json((await axios.get('https://api.example.com/rates')).data));
app.listen(3000);
