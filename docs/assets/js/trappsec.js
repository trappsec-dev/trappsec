function switchLang(lang) {
    // Update buttons
    document.querySelectorAll('.lang-btn').forEach(btn => {
        // Check if button text matches language (case-insensitive)
        const btnText = btn.textContent.toLowerCase();
        const isMatch = lang === 'node' ? btnText.includes('node') : btnText.includes('python');

        if (isMatch) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    // Update content
    document.querySelectorAll('.lang-content').forEach(content => {
        if (content.getAttribute('data-lang') === lang) {
            content.classList.add('active');
        } else {
            content.classList.remove('active');
        }
    });

    // Persist preference
    localStorage.setItem('trappsec_lang', lang);

    // Update URL state (without reloading)
    // This allows deep-linking to specific languages
    const url = new URL(window.location);
    url.searchParams.set('lang', lang);
    window.history.replaceState({}, '', url);
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Priority: 1. URL Param, 2. LocalStorage, 3. Default (python)
    const urlParams = new URLSearchParams(window.location.search);
    const langFromUrl = urlParams.get('lang');

    const savedLang = langFromUrl || localStorage.getItem('trappsec_lang') || 'python';
    switchLang(savedLang);
});
