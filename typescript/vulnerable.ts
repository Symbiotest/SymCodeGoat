import express, { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import { exec } from 'child_process';
import axios, { AxiosResponse } from 'axios';
import { MongoClient, Db } from 'mongodb';
import jwt from 'jsonwebtoken';
import _ from 'lodash';

// Configuration with hardcoded secrets (Security Misconfiguration)
const CONFIG = {
  PORT: 3000,
  MONGODB_URI: 'mongodb://localhost:27017/userdb',
  JWT_SECRET: 'insecure_jwt_secret_key_12345',
  UPLOAD_DIR: path.join(__dirname, 'uploads'),
  ADMIN_USERNAME: 'admin',
  ADMIN_PASSWORD: 'admin123' // Hardcoded credentials
};

// Initialize Express app
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection
let db: Db;
(async () => {
  try {
    const client = await MongoClient.connect(CONFIG.MONGODB_URI);
    db = client.db();
    console.log('Connected to MongoDB');
  } catch (err) {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  }
})();

// Middleware for "authentication" (Insecure Authentication)
const authenticate = (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    // Vulnerable: No token verification
    const decoded = jwt.decode(token);
    (req as any).user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// User registration with SQL Injection vulnerability
app.post('/api/register', async (req: Request, res: Response) => {
  const { username, password, email } = req.body;
  
  // Vulnerable to SQL Injection (if using SQL database)
  const query = `INSERT INTO users (username, password, email) VALUES ('${username}', '${password}', '${email}')`;
  
  try {
    // In a real app, this would be a database query
    console.log('Executing query:', query);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// File upload with Path Traversal vulnerability
app.post('/api/upload', authenticate, (req: Request, res: Response) => {
  const userId = (req as any).user?.id || 'anonymous';
  const { filename, content } = req.body;
  
  // Vulnerable to Path Traversal
  const filePath = path.join(CONFIG.UPLOAD_DIR, userId, filename);
  
  fs.writeFile(filePath, content, (err) => {
    if (err) {
      console.error('File upload error:', err);
      return res.status(500).json({ error: 'File upload failed' });
    }
    res.json({ message: 'File uploaded successfully' });
  });
});

// Profile endpoint with XSS vulnerability
app.get('/api/profile/:username', (req: Request, res: Response) => {
  const { username } = req.params;
  
  // Vulnerable to XSS
  const profileHtml = `
    <html>
      <head><title>${username}'s Profile</title></head>
      <body>
        <h1>Welcome, ${username}!</h1>
        <div id="profile">Loading profile data...</div>
      </body>
    </html>
  `;
  
  res.send(profileHtml);
});

// Command execution with Command Injection vulnerability
app.post('/api/execute', (req: Request, res: Response) => {
  const { command } = req.body;
  
  // Vulnerable to Command Injection
  exec(`utility_script.sh ${command}`, (error, stdout, stderr) => {
    if (error) {
      console.error('Command execution error:', error);
      return res.status(500).json({ error: 'Command execution failed' });
    }
    res.json({ output: stdout });
  });
});

// SSRF vulnerable endpoint
app.get('/api/fetch', async (req: Request, res: Response) => {
  const { url } = req.query;
  
  if (!url) {
    return res.status(400).json({ error: 'URL parameter is required' });
  }
  
  try {
    // Vulnerable to SSRF
    const response: AxiosResponse = await axios.get(url as string);
    res.json({ data: response.data });
  } catch (err) {
    console.error('Fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch URL' });
  }
});

// Insecure deserialization
app.post('/api/import', (req: Request, res: Response) => {
  const { data } = req.body;
  
  try {
    // Vulnerable to insecure deserialization
    const parsedData = JSON.parse(data);
    // Process the data...
    res.json({ success: true, data: parsedData });
  } catch (err) {
    res.status(400).json({ error: 'Invalid data format' });
  }
});

// Vulnerable dependency usage
app.get('/api/process', (req: Request, res: Response) => {
  const { input } = req.query;
  
  // Using a vulnerable version of lodash
  const result = _.merge({}, JSON.parse(input as string));
  
  res.json({ result });
});

// Start the server
app.listen(CONFIG.PORT, () => {
  console.log(`Server running on port ${CONFIG.PORT}`);
});