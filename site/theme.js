const preferenceKey = "getpatched-theme";
const root = document.documentElement;
const toggle = document.querySelector("[data-theme-toggle]");
const themeColor = document.querySelector('meta[name="theme-color"]');
const themeIcon = toggle?.querySelector("svg path");
const themeLabel = toggle?.querySelector("span");
const systemPreference = window.matchMedia("(prefers-color-scheme: dark)");
const moonPath = "M20.2 15.4A8.8 8.8 0 0 1 8.6 3.8 8.8 8.8 0 1 0 20.2 15.4Z";
const sunPath = "M12 3v2m0 14v2M5.64 5.64l1.41 1.41m9.9 9.9 1.41 1.41M3 12h2m14 0h2m-3.64-6.36-1.41 1.41m-9.9 9.9-1.41 1.41M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z";

function savedPreference() {
  try {
    return localStorage.getItem(preferenceKey);
  } catch {
    return null;
  }
}

function setTheme(theme, persist = false) {
  root.dataset.theme = theme;
  if (themeColor) themeColor.content = theme === "dark" ? "#07172f" : "#fffefa";
  if (toggle) {
    const actionLabel = theme === "dark" ? "Switch to light mode" : "Switch to dark mode";
    toggle.setAttribute("aria-label", actionLabel);
    toggle.setAttribute("title", actionLabel);
    if (themeLabel) themeLabel.textContent = theme === "dark" ? "Light mode" : "Dark mode";
    if (themeIcon) themeIcon.setAttribute("d", theme === "dark" ? sunPath : moonPath);
  }

  if (persist) {
    try {
      localStorage.setItem(preferenceKey, theme);
    } catch {
      // The selected theme remains active for this page when storage is unavailable.
    }
  }
}

if (toggle) {
  toggle.addEventListener("click", () => {
    setTheme(root.dataset.theme === "dark" ? "light" : "dark", true);
  });
}

setTheme(root.dataset.theme);

systemPreference.addEventListener("change", (event) => {
  if (savedPreference() !== "light" && savedPreference() !== "dark") {
    setTheme(event.matches ? "dark" : "light");
  }
});
