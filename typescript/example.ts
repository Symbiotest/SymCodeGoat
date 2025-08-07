// vulnerable.ts
// This file intentionally contains common OWASP Top 10 vulnerabilities for demonstration purposes only.

// Vulnerabilities included:
// 1. SQL Injection (A03:2021 - Injection)
// 2. Cross-Site Scripting (XSS) (A07:2021 - Identification and Authentication Failures)

import express from 'express';
import mysql from 'mysql';

const app = express();
app.use(express.urlencoded({ extended: true }));

// MySQL connection (example, do not use root/no password in production)
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'testdb'
});
db.connect();

// Vulnerability 1: SQL Injection
app.get('/user', (req, res) => {
  // User input is directly concatenated into SQL query
  const username = req.query.username;
  const sql = `SELECT * FROM users WHERE username = '${username}'`;
  db.query(sql, (err, results) => {
    if (err) {
      res.status(500).send('Database error');
      return;
    }
    res.json(results);
  });
});

// Vulnerability 2: Cross-Site Scripting (XSS)
app.post('/comment', (req, res) => {
  // Comment is not sanitized before being displayed
  const comment = req.body.comment;
  res.send(`<html><body><h1>Comment Received</h1><div>${comment}</div></body></html>`);
});

app.listen(3000, () => {
  console.log('Vulnerable app listening on port 3000');
});
