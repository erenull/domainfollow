// Main JavaScript for Domain Tracking Application

document.addEventListener('DOMContentLoaded', function() {
    // Auto-dismiss alerts after 5 seconds
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(function(alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);

    // Enable tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Add event listener to domain name input for validation
    const domainNameInput = document.getElementById('domain_name');
    if (domainNameInput) {
        domainNameInput.addEventListener('blur', function() {
            validateDomainName(this);
        });
    }

    // Add event listener to domain filter form
    const filterForm = document.querySelector('form[action*="dashboard"]');
    if (filterForm) {
        const resetButton = filterForm.querySelector('a.btn-secondary');
        resetButton.addEventListener('click', function(e) {
            e.preventDefault();
            const selects = filterForm.querySelectorAll('select');
            selects.forEach(select => {
                select.selectedIndex = 0;
            });
            filterForm.submit();
        });
    }
});

// Domain name validation function
function validateDomainName(input) {
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    const isValid = domainRegex.test(input.value);
    
    if (!isValid && input.value.trim() !== '') {
        input.classList.add('is-invalid');
        
        // Create or update validation message
        let feedbackElement = input.nextElementSibling;
        if (!feedbackElement || !feedbackElement.classList.contains('invalid-feedback')) {
            feedbackElement = document.createElement('div');
            feedbackElement.classList.add('invalid-feedback');
            input.parentNode.insertBefore(feedbackElement, input.nextSibling);
        }
        feedbackElement.textContent = 'Lütfen geçerli bir alan adı girin (örn: ornek.com)';
    } else {
        input.classList.remove('is-invalid');
        const feedbackElement = input.nextElementSibling;
        if (feedbackElement && feedbackElement.classList.contains('invalid-feedback')) {
            feedbackElement.remove();
        }
    }
    
    return isValid;
}

// Format dates in user's locale
function formatDate(dateString) {
    if (!dateString) return 'Bilinmiyor';
    
    const date = new Date(dateString);
    return date.toLocaleDateString('tr-TR', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric'
    });
}

// Calculate days remaining until expiry
function getDaysRemaining(expiryDateString) {
    if (!expiryDateString) return null;
    
    const expiryDate = new Date(expiryDateString);
    const today = new Date();
    
    // Set time to midnight for accurate day calculation
    expiryDate.setHours(0, 0, 0, 0);
    today.setHours(0, 0, 0, 0);
    
    const diffTime = expiryDate - today;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    return diffDays;
}

// Add warning class to domains expiring soon
function highlightExpiringDomains() {
    const domainRows = document.querySelectorAll('table tbody tr');
    
    domainRows.forEach(row => {
        const expiryDateCell = row.querySelector('td:nth-child(3)');
        if (!expiryDateCell) return;
        
        const expiryDateText = expiryDateCell.textContent.trim();
        if (expiryDateText === 'Bilinmiyor') return;
        
        // Parse the date (assuming format DD.MM.YYYY)
        const parts = expiryDateText.split('.');
        if (parts.length !== 3) return;
        
        const expiryDate = new Date(parts[2], parts[1] - 1, parts[0]);
        const today = new Date();
        
        // Calculate days remaining
        const diffTime = expiryDate - today;
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        
        // Add appropriate class based on days remaining
        if (diffDays <= 0) {
            row.classList.add('table-danger');
        } else if (diffDays <= 30) {
            row.classList.add('table-warning');
        }
    });
}

// Call the highlight function when the page loads
document.addEventListener('DOMContentLoaded', function() {
    highlightExpiringDomains();
});
