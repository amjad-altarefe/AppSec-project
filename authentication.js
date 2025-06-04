const User = require('./models/User');
require('dotenv').config();

const checkSession = (req, res, next) => {
    if (!req.session || !req.session.userId) {
        return res.status(401).send('Unauthorized');
    }
    next();
};

function checkAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    next();
  } else {
    res.status(403).send('Access denied');
  }
}

module.exports = {
    checkSession,
    checkAdmin
};