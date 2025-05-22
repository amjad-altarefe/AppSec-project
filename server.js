const express = require('express');
const path = require('path');

const app = express();
const PORT = 5000;

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

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
