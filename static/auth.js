"use strict";

async function submitAuth(form, endpoint, payload, errorNode) {
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  errorNode.textContent = "";
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Request failed.");
    window.location.assign("/");
  } catch (error) {
    errorNode.textContent = error.message;
    button.disabled = false;
  }
}

document.querySelectorAll("[data-toggle-password]").forEach((toggle) => {
  toggle.addEventListener("click", () => {
    const input = document.getElementById(toggle.dataset.togglePassword);
    const visible = input.type === "password";
    input.type = visible ? "text" : "password";
    toggle.setAttribute("aria-pressed", String(visible));
    toggle.setAttribute("aria-label", visible ? "Hide password" : "Show password");
    toggle.querySelector(".eye-open").hidden = visible;
    toggle.querySelector(".eye-closed").hidden = !visible;
  });
});

document.getElementById("login-form")?.addEventListener("submit", (event) => {
  event.preventDefault();
  submitAuth(event.currentTarget, "/api/auth/login", {
    email: document.getElementById("login-email").value,
    password: document.getElementById("login-password").value
  }, document.getElementById("login-error"));
});

document.getElementById("register-form")?.addEventListener("submit", (event) => {
  event.preventDefault();
  submitAuth(event.currentTarget, "/api/auth/register", {
    invite: document.getElementById("register-invite").value,
    email: document.getElementById("register-email").value,
    password: document.getElementById("register-password").value
  }, document.getElementById("register-error"));
});