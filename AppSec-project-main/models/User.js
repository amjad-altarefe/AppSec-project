const mongoose = require('mongoose');
const { encrypt, decrypt } = require('../encryption');




const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, required: true, unique: true },
    password: String,  role: {type: String, enum: ['admin', 'user'], default: 'user'}

});
module.exports = mongoose.model('User', userSchema);






//اذا ما زبط الي فوق جرب الي تحت




/*

const mongoose = require('mongoose');
const { encrypt, decrypt } = require('./encryption'); // تأكد من مسار الملف الصحيح

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        set: (name) => encrypt(name) // تشفير الاسم عند الحفظ
    },
    email: { 
        type: String, 
        required: true, 
        unique: true,
        set: (email) => encrypt(email.toLowerCase()) // تشفير الإيميل مع توحيد الحروف
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String, 
        enum: ['admin', 'user'], 
        default: 'user'
    },
    phone: {
        type: String,
        set: (phone) => phone ? encrypt(phone) : undefined, // تشفير اختياري للهاتف
        get: (phone) => phone ? decrypt(phone) : undefined
    },
    ssn: { // رقم الضمان الاجتماعي (مثال لبيانات حساسة)
        type: String,
        set: (ssn) => ssn ? encrypt(ssn) : undefined,
        get: (ssn) => ssn ? decrypt(ssn) : undefined,
        select: false // عدم إظهاره تلقائياً في الاستعلامات
    }
}, {
    toJSON: { getters: true }, // تفعيل الـ getters عند التحويل لـ JSON
    toObject: { getters: true } // تفعيل الـ getters عند التحويل لكائن
});

// Middleware لتشفير الباسورد قبل الحفظ
userSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        try {
            const salt = await bcrypt.genSalt(10);
            this.password = await bcrypt.hash(this.password, salt);
        } catch (err) {
            return next(err);
        }
    }
    next();
});

// دالة لمقارنة كلمات المرور (بعد فك التشفير إذا لزم الأمر)
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// دالة لاستعادة البيانات المشفرة بشكل آمن
userSchema.methods.getDecryptedData = function() {
    return {
        name: decrypt(this.name),
        email: decrypt(this.email),
        phone: this.phone ? decrypt(this.phone) : null,
        role: this.role // لا يحتاج تشفير
    };
};

module.exports = mongoose.model('User', userSchema);



*/