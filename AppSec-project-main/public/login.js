/* public/js/login.js */
document.addEventListener('DOMContentLoaded', () => {
  const form   = document.getElementById('login-form');
  const errBox = document.getElementById('error-message');

  /* عرض الخطأ القادم من السيرفر */
  const params = new URLSearchParams(window.location.search);
  if (params.has('error')) {
    errBox.textContent = decodeURIComponent(params.get('error'));
  }

  /* تحقّق بسيط قبل الإرسال */
  form.addEventListener('submit', e => {
    const email = sanitizeInput(document.getElementById('email').value);
    const pass  = sanitizeInput(document.getElementById('password').value);
    errBox.textContent = '';

    if (!isValidEmail(email)) {
      e.preventDefault();
      errBox.textContent = 'Invalid email format.';
    } else if (!isValidPassword(pass)) {
      e.preventDefault();
      errBox.textContent = 'Password must be at least 6 characters.';
    }
  });
});