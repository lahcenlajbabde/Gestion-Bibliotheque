// Minimal theme script placeholder
// Toggle 'dark' class on body when a button is wired to call toggleTheme()
function toggleTheme() {
    document.body.classList.toggle('dark');
}

// Expose to global for inline usage
window.toggleTheme = toggleTheme;
