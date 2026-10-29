(() => {
  const preferenceKey = "getpatched-theme";
  let preference = null;

  try {
    preference = localStorage.getItem(preferenceKey);
  } catch {
    // Storage can be unavailable in hardened browser contexts.
  }

  const theme = preference === "light" || preference === "dark"
    ? preference
    : window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light";

  document.documentElement.dataset.theme = theme;
  const themeColor = document.querySelector('meta[name="theme-color"]');
  if (themeColor) themeColor.content = theme === "dark" ? "#07172f" : "#fffefa";
})();
