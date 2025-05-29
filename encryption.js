const crypto = require('crypto');
require('dotenv').config();

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const IV_LENGTH = Number(process.env.IV_LENGTH);

// التحقق من صحة المفتاح (32 بايت)
function validateKey(key) {
    if (!key || Buffer.from(key, 'hex').length !== 32) {
        throw new Error('Encryption key must be 32 bytes long (64 hex chars) for AES-256');
    }
}

validateKey(ENCRYPTION_KEY);

// IV ثابت 16 بايت صفري (للتشفير الثابت)
const IV = Buffer.alloc(IV_LENGTH, 0);

// تشفير نص ثابت (deterministic encryption)
function encrypt(text) {
    const key = Buffer.from(ENCRYPTION_KEY, 'hex');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, IV);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;  // بدون IV لأن IV ثابت
}

// فك التشفير
function decrypt(encryptedText) {
    const key = Buffer.from(ENCRYPTION_KEY, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, IV);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

module.exports = {
    encrypt,
    decrypt
};
