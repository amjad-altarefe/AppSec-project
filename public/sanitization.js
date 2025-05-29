

// sanitization.js

// sanitize input with DOMPurify
function sanitizeInput(input) {
  return DOMPurify.sanitize(input.trim());
}

// validate email format
function isValidEmail(email) {
  const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$/i;;
  return regex.test(email);
}

// validate password strength (at least 6 chars)
function isValidPassword(password) {
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}$/;
  return regex.test(password);}

// validate full name (only letters and spaces)
function isValidName(name) {
  const regex = /^[A-Za-z\s]{2,}$/;
  return regex.test(name);
  //.
}






























/* >document.addEventListener('DOMContentLoaded', () => {
  const form = document.querySelector('form');
  if (!form) return; // إذا ما فيه فورم، يوقف السكربت

  form.addEventListener('submit', function (e) {
    // تعيين المتغيرات حسب وجود الحقول
    const nameInput = document.getElementById('name');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');

    // تحقق إذا الحقول موجودة
    if (nameInput) {
      const name = DOMPurify.sanitize(nameInput.value.trim());
      if (!name || name.length < 3) {
        alert("Please enter a valid name (at least 3 characters).");
        e.preventDefault();
        return;
      }
      nameInput.value = name;
    }

    if (emailInput) {
      const email = DOMPurify.sanitize(emailInput.value.trim());
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        alert("Please enter a valid email address.");
        e.preventDefault();
        return;
      }
      emailInput.value = email;
    }

    if (passwordInput) {
      const password = DOMPurify.sanitize(passwordInput.value);
      if (password.length < 6) {
        alert("Password must be at least 6 characters.");
        e.preventDefault();
        return;
      }
      passwordInput.value = password;
    }
  });
});
*/