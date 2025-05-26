const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const User = require('./models/User');
const bcrypt = require('bcrypt');
const session = require('express-session');
require('dotenv').config();
const { authenticateJWT, authorizeRoles } = require('./authentication');
const { encrypt, decrypt } = require('./public/utils/encryption');



const app = express();
const PORT=process.env.PORT;
const EMAIL = process.env.EMAIL
const SALT = process.env.SALT;
const secret = process.env.JWT_SECRET;

mongoose.connect('mongodb://127.0.0.1:27017/userDB', {
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
  //const { email, password } = req.body;
  const { name, email, password, role } = req.body;
  const user = new User({ name, email, password, role: role || 'user' });
  try {
    // 1. البحث عن المستخدم حسب الإيميل
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(401).send('User not found');
    }

    // 2. مقارنة كلمة المرور (إذا كانت مشفرة)
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).send('Invalid credentials');
    }

    req.session.userId = user._id;
    req.session.isAdmin = (email === EMAIL); // فقط هذا الإيميل admin
    //req.session.role    = user.role; 
    // 3. نجاح تسجيل الدخول
    if (req.session.isAdmin) {
      res.redirect('/admin');
    } else {
      res.send('Login successful!');
    }
    
    // لاحقًا: ممكن توليد JWT أو تفعيل session
  } catch (err) {
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
        const user = new User({ name, email, password: hashedPassword }); // <-- حفظ المشفّر
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
//✅ حذف مستخدم:
app.delete('/admin/users/:id', checkAdmin, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.send('User deleted');
  } catch (err) {
    res.status(500).send('Server error');
  }
});






// استيراد الـ middlewares
const { authenticateJWT, authorizeRoles, checkSession, checkAdmin } = require('./authentication');

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








app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});



const { encrypt, decrypt } = require('./encryption');

// مثال للتشفير
const sensitiveData = 'credit-card-number-1234';
const encryptedData = encrypt(sensitiveData);
console.log('Encrypted:', encryptedData);

// مثال لفك التشفير
const decryptedData = decrypt(encryptedData);
console.log('Decrypted:', decryptedData);

