const jwt = require('jsonwebtoken');
const User = require('./models/User');
require('dotenv').config();

// Middleware للمصادقة باستخدام JWT
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        
        jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
            if (err) {
                return res.sendStatus(403); // Forbidden
            }
            
            // التحقق من وجود المستخدم في قاعدة البيانات
            const user = await User.findById(decoded.userId);
            if (!user) {
                return res.sendStatus(403); // Forbidden
            }
            
            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401); // Unauthorized
    }
};

// Middleware للتحقق من الأدوار (Authorization)
const authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).send('Unauthorized');
        }
        
        if (!roles.includes(req.user.role)) {
            return res.status(403).send('Access denied');
        }
        
        next();
    };
};

// Middleware للتحقق من صحة الجلسة (للمسارات التي تستخدم الجلسات)
const checkSession = (req, res, next) => {
    if (!req.session || !req.session.userId) {
        return res.status(401).send('Unauthorized');
    }
    next();
};

// Middleware للتحقق من صلاحيات المدير
const checkAdmin = (req, res, next) => {
    if (!req.session || !req.session.isAdmin) {
        return res.status(403).send('Access denied');
    }
    next();
};

module.exports = {
    authenticateJWT,
    authorizeRoles,
    checkSession,
    checkAdmin
};