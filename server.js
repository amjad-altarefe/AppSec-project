const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const User = require('./models/User');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { body, validationResult } = require('express-validator');
require('dotenv').config();
const {checkAdmin, checkSession } = require('./authentication');
const { encrypt, decrypt } = require('./encryption');
const rateLimit = require('express-rate-limit');

const app = express();

const helmet = require('helmet');
app.use(helmet());
const cors = require('cors');
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", 'trusted-cdn.com'],
        styleSrc:   ["'self'", "'unsafe-inline'"], // ← هنا المفتاح!
    fontSrc: ["'self'", 'fonts.gstatic.com'],
    imgSrc: ["'self'", 'data:'],
  }
}));


const corsOptions = {
  origin: 'http://localhost:5000',      //    <--------------- ` http://localhost:${PORT} ` رح يطلع ايرور في عملية ال(run)
  methods: ['GET', 'POST'],
  credentials: true,
};

app.use(cors(corsOptions));
const PORT=process.env.PORT;
const EMAIL = process.env.EMAIL
const SALT = Number(process.env.SALT);
const secret = process.env.JWT_SECRET;
const MONGO_DB = process.env.MONGO_DB

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


// حد: 3 محاولات تسجيل دخول كل 15 دقيقة
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 3, // عدد المحاولات المسموح بها
  message: { message: 'Too many login attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(session({
  secret: process.env.JWT_SECRET, 
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',  // فعّلها في الإنتاج فقط
    sameSite: 'strict',  // أو 'lax' حسب احتياجك
    maxAge: 1000 * 60 * 15 // 15 دقيقة = 1000 ملي ثانية * 60 ثانية * 15  
    }
}));
app.post('/login', [
  body('email').matches( /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$/i)
  .withMessage('Invalid email format').normalizeEmail(),
  body('password')
  .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}$/)
  .withMessage('Incorrect password'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const message = errors.array().map(e => e.msg).join(', ');
    return res.redirect('/login?error=' + encodeURIComponent(message));
  }

  const { email, password } = req.body;

  try {
    const encryptedEmail = encrypt(email);
    const user = await User.findOne({ email: encryptedEmail });

    if (!user) {
      return res.redirect('/login?error=' + encodeURIComponent('User not found'));
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.redirect('/login?error=' + encodeURIComponent('Invalid credentials'));
    }

    req.session.regenerate(function(err) {
      if (err) return res.redirect('/login?error=' + encodeURIComponent('Session error'));

      req.session.userId = user._id;
      req.session.role = user.role;

      if (user.role === 'admin') {
        req.session.isAdmin = true;
        return res.redirect('/admin');
      }

      return res.redirect('/home');
    });

  } catch (err) {
    console.error("Login error:", err);
    return res.redirect('/login?error=' + encodeURIComponent('Server error'));
  }
});
app.post('/register',[ body('name').matches(/^[A-Za-z\s]{2,}$/).withMessage('Invalid Name format'),
  body('email').matches( /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$/i)
  .withMessage('Invalid email format').normalizeEmail(),
  body('password')
  .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}$/)
  .withMessage('Password must be at least 8 characters and include:\n• One uppercase letter\n• One lowercase letter\n• One special character')
,], 
  async (req, res) => {
  
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      // إذا في أخطاء، رجعها للمستخدم
     const msg = errors.array()[0].msg;
      return res.redirect('/register.html?error=' + encodeURIComponent(msg));
    }

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.redirect(
        '/register.html?error=' + encodeURIComponent('All fields are required')
      );
    }

    try {
        const hashedPassword = await bcrypt.hash(password, SALT); // <-- تشفير الباسورد
        const encryptedEmail = encrypt(email);
        const user = new User({ name, email: encryptedEmail, password: hashedPassword, role: 'user' }); // <-- حفظ المشفّر
        await user.save();

        return res.redirect(
        '/login.html?success=' + encodeURIComponent('User registered successfully. Please log in.')
      );
    } catch (err) {
        if (err.code === 11000) {
            return res.redirect(
          '/register.html?error=' + encodeURIComponent('Email already exists.')
        );
      }
      console.error('Registration error:', err);
      return res.redirect(
        '/register.html?error=' + encodeURIComponent('Something went wrong.')
      );
    }
});

// ملفات static مثل html, css, js
app.use(express.static(path.join(__dirname, 'public')));

// الراوت الرئيسي يفتح login.html
app.get('/',loginLimiter, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


// راوت login
app.get('/login',loginLimiter, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// راوت register
app.get('/register',loginLimiter, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid'); // ← مهم لمسح الكوكي
    res.redirect('/login');
  });
});



app.get('/admin',loginLimiter, checkAdmin,checkSession, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
//✅ عرض جميع المستخدمين:
app.get('/admin/users',loginLimiter, checkAdmin,checkSession, async (req, res) => {
  try {
    const users = await User.find();
    const decryptedUsers = users.map(user => ({
      _id: user._id,
      name: user.name,  
      email: decrypt(user.email), // ← فك التشفير
      role: user.role
    }));  
    res.json(decryptedUsers); // ترسل البيانات كـ JSON
  } catch (err) {
    res.status(500).send('Server error');
  }
});
app.get('/home',loginLimiter, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

//✅ حذف مستخدم:
app.delete('/admin/users/:id', checkAdmin,checkSession, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.send('User deleted');
  } catch (err) {
    res.status(500).send('Server error');
  } 
});

// استخدامها في المسارات

app.get('/api/user',loginLimiter, (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });

  User.findById(req.session.userId)
    .then(user => {
      if (!user) return res.status(404).json({ error: 'User not found' });
      res.json({ name: user.name, email: decrypt(user.email), role: user.role });
    })
    .catch(() => res.status(500).json({ error: 'Server error' }));
});


app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
