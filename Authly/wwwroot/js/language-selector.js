/* JavaScript helper for language selector */
window.addLanguageSelectorHandler = function(dotNetRef) {
    function handleClickOutside(event) {
        const languageSelector = event.target.closest('.language-selector');
        if (!languageSelector) {
            dotNetRef.invokeMethodAsync('CloseDropdown');
        }
    }
    
    document.addEventListener('click', handleClickOutside);
    
    // Store reference for cleanup
    window.languageSelectorCleanup = function() {
        document.removeEventListener('click', handleClickOutside);
    };
};

// Initialize culture from localStorage on page load
window.addEventListener('DOMContentLoaded', function() {
    const savedLanguage = localStorage.getItem('selectedLanguage');
    if (savedLanguage) {
        const supportedCultures = ['en-US', 'cs-CZ', 'de-DE', 'fr-FR'];
        if (supportedCultures.includes(savedLanguage)) {
            // Set ASP.NET Core localization cookie
            const cookieValue = `c=${savedLanguage}|uic=${savedLanguage}`;
            document.cookie = `.AspNetCore.Culture=${cookieValue}; path=/; expires=${new Date(Date.now() + 365*24*60*60*1000).toUTCString()}`;
        }
    }
});