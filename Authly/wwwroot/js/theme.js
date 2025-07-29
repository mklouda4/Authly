window.themeHelper = {
    getSystemTheme: function () {
        try {
            if (typeof window.matchMedia === 'function') {
                return window.matchMedia('(prefers-color-scheme: dark)').matches;
            }
            return false; // fallback pro starší prohlížeče
        } catch (error) {
            console.warn('Error detecting system theme preference:', error);
            return false;
        }
    }
};