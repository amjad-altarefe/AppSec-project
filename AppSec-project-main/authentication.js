const User = require('./models/User');
require('dotenv').config();
// Middleware للتحقق من صحة الجلسة (للمسارات التي تستخدم الجلسات)
const checkSession = (req, res, next) => {
    if (!req.session || !req.session.userId) {
        return res.status(401).send('Unauthorized');
    }
    next();
};

// Middleware للتحقق من صلاحيات المدير
function checkAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    next(); // السماح بالوصول
  } else {
    res.status(403).send('Access denied');
  }
}

module.exports = {
    checkSession,
    checkAdmin
};