// sanitization.js

window.sanitizeInput = function(input) {
  return DOMPurify.sanitize(input.trim());
};

window.isValidEmail = function(email) {
  const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$/i;
  return regex.test(email);
};

window.isValidPassword = function(password) {
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}$/;
  return regex.test(password);
};

window.isValidName = function(name) {
  const regex = /^[A-Za-z\s]{2,}$/;
  return regex.test(name);
};
