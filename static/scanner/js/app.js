/* PortScope — global JS */

// CSRF helper
function getCsrf() {
  return document.cookie.split(';')
    .map(c => c.trim())
    .find(c => c.startsWith('csrftoken='))
    ?.split('=')[1] || '';
}

// Auto-highlight active nav items
document.addEventListener('DOMContentLoaded', () => {
  const path = window.location.pathname;
  document.querySelectorAll('.nav-item').forEach(el => {
    const href = el.getAttribute('href');
    if (href && path.startsWith(href) && href !== '/') {
      el.classList.add('active');
    } else if (href === '/' && path === '/') {
      el.classList.add('active');
    }
  });
});
