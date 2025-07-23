// Clipboard functionality
window.clipboardHelper = {
    copyText: async function(text) {
        try {
            if (navigator.clipboard && window.isSecureContext) {
                // Use modern clipboard API
                await navigator.clipboard.writeText(text);
                return true;
            } else {
                // Fallback for older browsers or non-secure contexts
                const textArea = document.createElement("textarea");
                textArea.value = text;
                textArea.style.position = "fixed";
                textArea.style.opacity = "0";
                textArea.style.left = "-999999px";
                textArea.style.top = "-999999px";
                document.body.appendChild(textArea);
                textArea.focus();
                textArea.select();
                const result = document.execCommand('copy');
                document.body.removeChild(textArea);
                return result;
            }
        } catch (err) {
            console.error('Failed to copy text: ', err);
            return false;
        }
    }
};

// Toast Notification System
window.toastHelper = {
    toastContainer: null,
    toastId: 0,

    init: function() {
        if (!this.toastContainer) {
            this.toastContainer = document.createElement('div');
            this.toastContainer.className = 'toast-container';
            document.body.appendChild(this.toastContainer);
        }
    },

    show: function(message, type = 'info', duration = 4000, title = null) {
        this.init();
        
        const toastId = ++this.toastId;
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.setAttribute('data-toast-id', toastId);

        // Create icon based on type
        const iconSvg = this.getIcon(type);
        
        // Create toast content
        const toastContent = document.createElement('div');
        toastContent.className = 'toast-content';
        
        if (title) {
            const titleElement = document.createElement('div');
            titleElement.className = 'toast-title';
            titleElement.textContent = title;
            toastContent.appendChild(titleElement);
        }
        
        const messageElement = document.createElement('div');
        messageElement.className = 'toast-message';
        messageElement.textContent = message;
        toastContent.appendChild(messageElement);

        // Create close button
        const closeButton = document.createElement('button');
        closeButton.className = 'toast-close';
        closeButton.innerHTML = '<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path></svg>';
        closeButton.onclick = () => this.hide(toastId);

        // Assemble toast
        toast.appendChild(iconSvg);
        toast.appendChild(toastContent);
        toast.appendChild(closeButton);

        // Add progress bar for auto-dismiss
        if (duration > 0) {
            const progressBar = document.createElement('div');
            progressBar.className = 'toast-progress';
            progressBar.style.animationDuration = `${duration}ms`;
            toast.appendChild(progressBar);
        }

        // Add to container
        this.toastContainer.appendChild(toast);

        // Auto-dismiss
        if (duration > 0) {
            setTimeout(() => this.hide(toastId), duration);
        }

        // Manual dismiss on click
        toast.onclick = () => this.hide(toastId);

        return toastId;
    },

    hide: function(toastId) {
        const toast = document.querySelector(`[data-toast-id="${toastId}"]`);
        if (toast) {
            toast.classList.add('toast-hiding');
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }
    },

    getIcon: function(type) {
        const iconContainer = document.createElement('div');
        iconContainer.className = 'toast-icon';
        
        let iconPath = '';
        switch (type) {
            case 'success':
                iconPath = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>';
                break;
            case 'error':
                iconPath = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>';
                break;
            case 'warning':
                iconPath = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z"></path>';
                break;
            case 'info':
            default:
                iconPath = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>';
                break;
        }
        
        iconContainer.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor">${iconPath}</svg>`;
        return iconContainer;
    },

    success: function(message, title = null, duration = 4000) {
        return this.show(message, 'success', duration, title);
    },

    error: function(message, title = null, duration = 5000) {
        return this.show(message, 'error', duration, title);
    },

    warning: function(message, title = null, duration = 4500) {
        return this.show(message, 'warning', duration, title);
    },

    info: function(message, title = null, duration = 4000) {
        return this.show(message, 'info', duration, title);
    },

    clear: function() {
        if (this.toastContainer) {
            this.toastContainer.innerHTML = '';
        }
    }
};