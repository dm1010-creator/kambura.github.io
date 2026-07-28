(function () {
  const burger = document.getElementById('burgerBtn');
  const mobileMenu = document.getElementById('mobileMenu');
  const menuClose = document.getElementById('menuClose');
  const main = document.getElementById('mainContent');
  let lastFocused = null;

  const FOCUSABLE_SELECTORS = 'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])';

  function openMenu() {
    lastFocused = document.activeElement;
    mobileMenu.removeAttribute('hidden');
    burger.setAttribute('aria-expanded', 'true');
    // trap initial focus to container
    const inner = mobileMenu.querySelector('.mobile-menu-inner');
    inner.focus();
    document.body.style.overflow = 'hidden'; // prevent background scroll
    document.addEventListener('keydown', onKeyDown);
    // Mark main as inert for screen readers
    main.setAttribute('aria-hidden', 'true');
    trapFocus(inner);
  }

  function closeMenu() {
    mobileMenu.setAttribute('hidden', '');
    burger.setAttribute('aria-expanded', 'false');
    document.body.style.overflow = '';
    document.removeEventListener('keydown', onKeyDown);
    main.removeAttribute('aria-hidden');
    if (lastFocused) lastFocused.focus();
  }

  function onKeyDown(e) {
    if (e.key === 'Escape') {
      closeMenu();
    }
  }

  function trapFocus(container) {
    const focusable = Array.from(container.querySelectorAll(FOCUSABLE_SELECTORS));
    if (!focusable.length) return;

    function handleTab(e) {
      if (e.key !== 'Tab') return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
    container.addEventListener('keydown', handleTab);
    // cleanup when closed
    const observer = new MutationObserver(() => {
      if (mobileMenu.hasAttribute('hidden')) {
        container.removeEventListener('keydown', handleTab);
        observer.disconnect();
      }
    });
    observer.observe(mobileMenu, { attributes: true, attributeFilter: ['hidden'] });
  }

  // Event listeners
  burger.addEventListener('click', openMenu);
  menuClose.addEventListener('click', closeMenu);

  // Close when a navigation link is activated (capture for SPA-friendly behavior)
  mobileMenu.addEventListener('click', function (e) {
    const a = e.target.closest('a');
    if (a) {
      // Allow normal navigation; close menu so screen readers regain context
      closeMenu();
    }
  });

  // If user tab-focuses the burger (keyboard), ensure aria-expanded is accurate
  window.addEventListener('DOMContentLoaded', () => {
    if (!burger.hasAttribute('aria-expanded')) burger.setAttribute('aria-expanded', 'false');
  });
})();
