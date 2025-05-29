const crypto = require('crypto');
require('dotenv').config();

// يجب تخزين هذه المفتاح في ملف .env وعدم مشاركته
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const IV_LENGTH = Number(process.env.IV_LENGTH); // طول متجه التهيئة لـ AES

// تأكد من أن مفتاح التشفير بطول صحيح (32 بايت لـ AES-256)
function validateKey(key) {
    if (!key || key.length !== 32) {
        throw new Error('Encryption key must be 32 characters long for AES-256');
    }
}

// تشفير النص
function encrypt(text) {
    try {
        validateKey(ENCRYPTION_KEY);
        
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(
            'aes-256-cbc', 
            Buffer.from(ENCRYPTION_KEY), 
            iv
        );
        
        let encrypted = cipher.update(text);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        return iv.toString('hex') + ':' + encrypted.toString('hex');
    } catch (error) {
        console.error('Encryption failed:', error);
        throw error;
    }
}

// فك تشفير النص
function decrypt(text) {
    try {
        validateKey(ENCRYPTION_KEY);
        
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv(
            'aes-256-cbc', 
            Buffer.from(ENCRYPTION_KEY), 
            iv
        );
        
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        return decrypted.toString();
    } catch (error) {
        console.error('Decryption failed:', error);
        throw error;
    }
}

// توليد مفتاح تشفير عشوائي (للاستخدام مرة واحدة عند الإعداد الأولي)
function generateEncryptionKey() {
    return crypto.randomBytes(32).toString('hex');
}

// تشفير كائن كامل (مثلاً بيانات المستخدم)
function encryptData(data) {
    if (typeof data === 'object') {
        data = JSON.stringify(data);
    }
    return encrypt(data);
}

// فك تشفير كائن كامل
function decryptData(encryptedData) {
    const decrypted = decrypt(encryptedData);
    try {
        return JSON.parse(decrypted);
    } catch {
        return decrypted;
    }
}

module.exports = {
    encrypt,
    decrypt,
    generateEncryptionKey,
    encryptData,
    decryptData
};