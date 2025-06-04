document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("register-form");
  const errorBox = document.getElementById("error-message");

  form.addEventListener("submit", function (e) {
    const name = sanitizeInput(document.getElementById("name").value);
    const email = sanitizeInput(document.getElementById("email").value);
    const password = sanitizeInput(document.getElementById("password").value);
    errorBox.textContent = "";

    if (!name) {
      e.preventDefault();
      errorBox.textContent = "Name is required.";
    } else if (!isValidEmail(email)) {
      e.preventDefault();
      errorBox.textContent = "Invalid email format.";
    } else if (!isValidPassword(password)) {
      e.preventDefault();
      errorBox.textContent =
        "Password must be at least 8 characters and include:\n• One uppercase letter\n• One lowercase letter\n• One special character";
    }
  });

  const queryParams = new URLSearchParams(window.location.search);
  const serverError = queryParams.get("error");
  if (serverError) {
    errorBox.textContent = decodeURIComponent(serverError.replace(/\+/g, " "));
  }
});
