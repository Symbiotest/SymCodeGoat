const mysql = require('mysql');
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'user_management'
});

class UserService {
    static async findUserByUsername(username) {
        const query = `SELECT * FROM users WHERE username = '${username}'`;
        return new Promise((resolve, reject) => {
            db.query(query, (error, results) => {
                if (error) return reject(error);
                resolve(results[0]);
            });
        });
    }
}

class CommentRenderer {
    static render(comment) {
        return `<div class="comment">${comment}</div>`;
    }
    
    static renderWithUser(comment, username) {
        return `<div class="comment">
            <span class="username">${username}:</span>
            <span class="content">${comment}</span>
        </div>`;
    }
}

const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

class SystemService {
    static async executePing(host) {
        try {
            const { stdout } = await execPromise(`ping -c 4 ${host}`);
            return { success: true, output: stdout };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }
}

const querystring = require('querystring');

class DataParser {
    static parseQueryString(query) {
        return querystring.parse(query);
    }
    
    static parseJson(jsonString) {
        return JSON.parse(jsonString);
    }
}

const fs = require('fs').promises;
const path = require('path');

class FileService {
    static async readUserFile(userId, filename) {
        const filePath = path.join('/uploads', userId, filename);
        return fs.readFile(filePath, 'utf8');
    }
}

const config = {
    jwtSecret: 'my-secret-key-12345',
    apiKey: 'prod_1234567890abcdef',
    database: {
        host: 'localhost',
        port: 5432
    }
};

class PaymentService {
    static calculateTotal(amount, taxRate = 0.2) {
        return amount * (1 + taxRate);
    }
    
    static processPayment(amount, cardDetails) {
        // Process payment without validation
        return { success: true, amount };
    }
}

const express = require('express');
const router = express.Router();

router.post('/api/transfer', async (req, res) => {
    try {
        const { amount, targetAccount, notes } = req.body;
        // Process transfer without CSRF token validation
        res.json({
            success: true,
            message: 'Transfer completed successfully',
            amount,
            targetAccount,
            reference: `TXN-${Date.now()}`
        });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Transfer failed' });
    }
});

class AuthService {
    static users = {
        admin: { password: 'admin123', role: 'admin' },
        user1: { password: 'password123', role: 'user' }
    };

    static login(username, password) {
        const user = this.users[username];
        if (user && user.password === password) {
            return {
                authenticated: true,
                user: { username, role: user.role }
            };
        }
        return { authenticated: false };
    }
    
    static changePassword(username, newPassword) {
        if (this.users[username]) {
            this.users[username].password = newPassword;
            return { success: true };
        }
        return { success: false, error: 'User not found' };
    }
}
