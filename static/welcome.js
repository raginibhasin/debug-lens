"use strict";

document.getElementById("logout")?.addEventListener("click", async () => {
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const response = await fetch("/api/auth/logout", {
    method: "POST",
    headers: { "X-CSRF-Token": csrf }
  });
  if (response.ok) window.location.assign("/login");
});