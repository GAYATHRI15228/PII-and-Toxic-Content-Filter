// Script to enable smooth form submission feedback
document.addEventListener("DOMContentLoaded", function () {
    const submitBtn = document.querySelector('.submit-btn');
    const form = document.querySelector('form');
    
    form.addEventListener('submit', function() {
        submitBtn.innerHTML = "Processing...";
        submitBtn.disabled = true;
    });
});

// Smooth scroll to top for better UX when form is submitted
document.querySelector('.submit-btn').addEventListener('click', function (e) {
    e.preventDefault();
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
});
