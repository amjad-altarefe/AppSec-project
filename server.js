const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const User = require('./models/User');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { body, validationResult } = require('express-validator');
require('dotenv').config();
const { authenticateJWT, authorizeRoles, checkSession } = require('./authentication');
const { encrypt, decrypt } = require('./encryption');

const app = express();
const PORT=process.env.PORT;
const EMAIL = process.env.EMAIL
const SALT = Number(process.env.SALT);
const secret = process.env.JWT_SECRET;

mongoose.connect('mongodb://127.0.0.1:27017/myapp', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("✅ Connected to MongoDB");
}).catch(err => {
    console.error("❌ Failed to connect to MongoDB", err);
});


app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.JWT_SECRET, 
  resave: false,
  saveUninitialized: false
}));

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare( password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    req.session.userId = user._id;
    req.session.role = user.role;

    // فقط إذا كان المستخدم هو أدمن
    // في السيرفر
if (user.role === 'admin') {
  req.session.isAdmin = true;
  return res.status(200).json({ redirect: '/admin' });
}
// مستخدم عادي
return res.status(200).json({ redirect: '/home' });


  } catch (err) {
    console.error("Login error:", err);
    res.status(500).send('Server error');
  }
});

function checkAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    next(); // السماح بالوصول
  } else {
    res.status(403).send('Access denied');
  }
}

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).send("All fields are required.");
    }

    try {
        const hashedPassword = await bcrypt.hash(password, SALT); // <-- تشفير الباسورد
        const user = new User({ name, email, password: hashedPassword, role: 'user' }); // <-- حفظ المشفّر
        await user.save();

        res.status(201).send("User registered successfully.");
    } catch (err) {
        if (err.code === 11000) {
            res.status(409).send("Email already exists.");
        } else {
            res.status(500).send("Something went wrong.");
        }
    }
});

// ملفات static مثل html, css, js
app.use(express.static(path.join(__dirname, 'public')));

// الراوت الرئيسي يفتح login.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// راوت login
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// راوت register
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin', checkAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
//✅ عرض جميع المستخدمين:
app.get('/admin/users', checkAdmin, async (req, res) => {
  try {
    const users = await User.find();
    res.json(users); // ترسل البيانات كـ JSON
  } catch (err) {
    res.status(500).send('Server error');
  }
});
app.get('/home', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

//✅ حذف مستخدم:
app.delete('/admin/users/:id', checkAdmin, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.send('User deleted');
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// استخدامها في المسارات
app.get('/protected-route', authenticateJWT, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});

app.get('/admin-only', authenticateJWT, authorizeRoles('admin'), (req, res) => {
    res.json({ message: 'Admin dashboard', user: req.user });
});

// أو للمسارات التي تستخدم الجلسات
app.get('/profile', checkSession, (req, res) => {
    // عرض صفحة الملف الشخصي
});


//const { encrypt, decrypt } = require('./encryption');

// مثال للتشفير
const sensitiveData = 'credit-card-number-1234';
const encryptedData = encrypt(sensitiveData);
console.log('Encrypted:', encryptedData);

// مثال لفك التشفير
const decryptedData = decrypt(encryptedData);
console.log('Decrypted:', decryptedData);


app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
