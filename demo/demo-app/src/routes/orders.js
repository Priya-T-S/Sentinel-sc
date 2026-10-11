const express = require('express');
const { merge } = require('lodash');

const router = express.Router();
const defaults = { currency: 'USD', priority: 'normal' };

// Merges untrusted JSON into defaults (prototype pollution sink in old lodash).
router.post('/', (req, res) => {
  const order = merge({}, defaults, req.body);
  res.status(201).json(order);
});

module.exports = router;
