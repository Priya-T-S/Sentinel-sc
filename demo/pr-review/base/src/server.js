const express = require('express');
const _ = require('lodash');
const app = express();
app.get('/health', (req, res) => res.json({ ok: true, at: _.now() }));
app.listen(3000);
