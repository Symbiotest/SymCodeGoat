import express from 'express';
import fs from 'fs';
import path from 'path';
import { exec } from 'child_process';
import axios from 'axios';

const app = express();
app.use(express.json());

// A1: Broken Access Control
app.get('/admin', (req, res) => {
  const role = req.query.role;
  if (role === 'admin') {
    res.send('Welcome, admin!');
  } else {
    // Broken access control: no enforcement
    res.send('You should not see this, but here’s the admin data.');
  }
});

// A2: Cryptographic Failures
app.post('/store-password', (req, res) => {
  const password = req.body.password;
  // Base64 is NOT encryption
  const encoded = Buffer.from(password).toString('base64');
  res.send(`Stored encoded password: ${encoded}`);
});

// A3: Injection (SQL, NoSQL, etc.)
app.get('/user', (req, res) => {
  const username = req.query.username;
  // Example of NoSQL injection
  const query = { username: username };  // vulnerable if passed directly to MongoDB
  res.send(`Queried user: ${JSON.stringify(query)}`);
});

// A4: Insecure Design
app.post('/reset-password', (req, res) => {
  // No auth, no rate limit, no verification
  res.send('Password reset link sent!');
});

// A5: Security Misconfiguration
app.get('/file', (req, res) => {
  const filePath = path.join(__dirname, 'public', req.query.name as string); // vulnerable to directory traversal
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return res.status(404).send('File not found');
    res.send(data);
  });
});

// A6: Vulnerable and Outdated Components
app.get('/vulnerable-lib', (req, res) => {
  // Assume an outdated package like lodash <4.17.21
  const _ = require('lodash');
  const arr = [1];
  res.send(`Lodash result: ${_.flattenDeep(arr)}`);
});

// A7: Identification and Authentication Failures
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === '123456') {  // weak password
    res.send('Logged in!');
  } else {
    res.status(401).send('Invalid credentials');
  }
});

// A8: Software and Data Integrity Failures
app.post('/install-plugin', (req, res) => {
  const pluginName = req.body.plugin;
  // No integrity or signature check
  exec(`npm install ${pluginName}`, (err, stdout, stderr) => {
    if (err) return res.status(500).send('Error installing plugin');
    res.send(`Plugin installed: ${stdout}`);
  });
});

// A9: Security Logging and Monitoring Failures
app.post('/transfer', (req, res) => {
  const { amount } = req.body;
  // No logging at all
  res.send(`Transferred ${amount}€`);
});

// A10: Server-Side Request Forgery (SSRF)
app.get('/fetch-url', async (req, res) => {
  const targetUrl = req.query.url as string;
  try {
    const response = await axios.get(targetUrl); // SSRF vulnerability
    res.send(response.data);
  } catch (err) {
    res.status(500).send('Error fetching URL');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});